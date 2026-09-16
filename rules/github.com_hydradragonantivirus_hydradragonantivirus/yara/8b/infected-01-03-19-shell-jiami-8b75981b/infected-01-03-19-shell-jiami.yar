rule infected_01_03_19_shell_jiami {
  meta:
    description = "shell - file jiami.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-03"
    hash1       = "96361377d3b4d593397fdbe193af550dd94086c0990cc59c471d449cbf2aa315"

  strings:
    $s1  = "<?php /* PHP Encode by  http://Www.PHPJiaMi.Com/ */error_reporting(0);ini_set(\"display_errors\", 0);if(!defined('adggarmc')){de" ascii
    $s2  = "<?php /* PHP Encode by  http://Www.PHPJiaMi.Com/ */error_reporting(0);ini_set(\"display_errors\", 0);if(!defined('adggarmc')){de" ascii
    $s3  = "WEZBTFBVWV" fullword ascii  
    $s4  = "YZGBUXERY" fullword ascii  
    $s5  = "ZGBUXERYZF" fullword ascii  
    $s6  = "RHRFLDVESX" fullword ascii  
    $s7  = "LDRBWVFBPU" fullword ascii  
    $s8  = "LDRAXGBZMU" fullword ascii  
    $s9  = "ZCRVMGBFVEF" fullword ascii  
    $s10 = "ERGVQMTBB" fullword ascii  
    $s11 = "FPABIXHRQ" fullword ascii  
    $s12 = "RVFZRVBHVF" fullword ascii  
    $s13 = "TUVNPVBZPS1" fullword ascii  
    $s14 = "YZGBUXERYZE1" fullword ascii  
    $s15 = "VXV1FLWVIJDVFXWE" fullword ascii  
    $s16 = "AZFRJRVVYQH1" fullword ascii  
    $s17 = "OUZLW1RMQF" fullword ascii  
    $s18 = "XC1YQWF5NR" fullword ascii  
    $s19 = "PD44P0Q6O2" fullword ascii  
    $s20 = "Q1REN2FTL1Z" fullword ascii  

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 300KB and
      (2 of them)
    ) or (all of them)
}