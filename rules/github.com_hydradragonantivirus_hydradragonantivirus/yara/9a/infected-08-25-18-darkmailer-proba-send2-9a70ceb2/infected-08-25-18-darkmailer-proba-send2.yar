rule infected_08_25_18_darkmailer__proba_send2 {
  meta:
    description = ".proba - file send2.pl"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-25"
    hash1       = "1f03fcef96ec0b0300e4b2adfdcf19bb7767afbb08f0e0d528def7cfa0dec323"

  strings:
    $s1 = "my $processid = $forkmanager->start() and next;" fullword ascii
    $s2 = "my $Subject = 'REVENUE Tax refund - 490,99 EUR'; # subject for mails" fullword ascii
    $s3 = "print \"perl send.pl <email_body_file> <email_list_file> <threads>\\n\";" fullword ascii
    $s4 = "'content-type' => \"text/html; charset=\\\"iso-8859-1\\\"\"" fullword ascii
    $s5 = "print \"It works like this:\\n\";" fullword ascii
    $s6 = "my $From = '--REVENUE--<support@deliveroo.ie>'; # from addr" fullword ascii
    $s7 = "print \"[+][\".(localtime).\"] Started with $threads threads \\n\\n\";" fullword ascii
    $s8 = "my $forkmanager = new Parallel::ForkManager($threads);" fullword ascii
    $s9 = "if  (!$threads){ $threads = \"10\";}" fullword ascii

  condition:
    (uint16(0) == 0x7375 and
      filesize < 4KB and
      (all of them)
    ) or (all of them)
}