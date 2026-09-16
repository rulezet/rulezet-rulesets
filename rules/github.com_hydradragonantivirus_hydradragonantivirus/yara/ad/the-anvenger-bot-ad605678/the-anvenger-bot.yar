rule The_anvenger_Bot {
  meta:
    description = "mass-bot-exploite-master - file The anvenger Bot.zip"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-15"
    hash1       = "1d2e4ef7f9d92bfe786477cb744cef76782195f62efa24e8f2ff38d69534a94b"

  strings:
    $s1  = ".git/logs/refs/remotes/origin/HEAD" fullword ascii
    $s2  = ".git/logs/refs/heads/master" fullword ascii
    $s3  = ".git/logs/refs/remotes/origin/PK" fullword ascii
    $s4  = ".git/refs/remotes/origin/HEAD+JM" fullword ascii
    $s5  = ".git/logs/refs/heads/PK" fullword ascii
    $s6  = ".git/logs/refs/heads/" fullword ascii
    $s7  = "mycookies.txt" fullword ascii
    $s8  = ".git/logs/HEAD" fullword ascii
    $s9  = ".git/logs/refs/remotes/PK" fullword ascii
    $s10 = ".git/logs/refs/remotes/origin/" fullword ascii
    $s11 = ".git/refs/remotes/origin/HEAD" fullword ascii
    $s12 = ".git/logs/refs/remotes/" fullword ascii
    $s13 = "magento.php" fullword ascii
    $s14 = ".git/hooks/prepare-commit-msg.sampleuS]O" fullword ascii
    $s15 = ".git/hooks/post-update.sample-" fullword ascii
    $s16 = ".git/hooks/post-update.sample" fullword ascii
    $s17 = "mycookies.txtS" fullword ascii
    $s18 = ".git/hooks/prepare-commit-msg.sample" fullword ascii
    $s19 = ".git/hooks/pre-commit.samplemTao" fullword ascii
    $s20 = "www~~~" fullword ascii  

  condition:
    (uint16(0) == 0x4b50 and
      filesize < 1000KB and
      (8 of them)
    ) or (all of them)
}