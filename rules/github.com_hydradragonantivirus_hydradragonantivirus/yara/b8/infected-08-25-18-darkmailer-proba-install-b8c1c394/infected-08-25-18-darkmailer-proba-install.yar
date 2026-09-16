rule infected_08_25_18_darkmailer__proba_install {
  meta:
    description = ".proba - file install.sh"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-25"
    hash1       = "25d996431965b818ade25fc03fdb756e6e58306bddcda7e32b1f69dcb5d4846e"

  strings:
    $s1 = "wget -O-  --no-check-certificate http://cpanmin.us | perl - -l ~/perl5 App::cpanminus local::lib" fullword ascii
    $s2 = "echo 'eval `perl -I ~/perl5/lib/perl5 -Mlocal::lib`' >> ~/.profile" fullword ascii
    $s3 = "declare -x HOME=\"$this\"" fullword ascii
    $s4 = "echo 'export MANPATH=$HOME/perl5/man:$MANPATH' >> ~/.profile" fullword ascii
    $s5 = "eval `perl -I ~/perl5/lib/perl5 -Mlocal::lib`" fullword ascii

  condition:
    (uint16(0) == 0x2123 and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}