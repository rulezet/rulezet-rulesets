rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aiy413e_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aiy413e_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b55792ddd726fa24644b321f50774b5eef0779fd235624e55a27442c46dc50cb"

  strings:
    $s1  = "explorer \"http://www.haansoft.com/hnc4_0/haansoft/support/regist_cs.php\"" fullword ascii
    $s2  = "explorer \"%sHNC\\Readme\\%s\"" fullword ascii
    $s3  = "explorer \"%s\"" fullword ascii
    $s4  = "InstallExe Version 1.0" fullword wide
    $s5  = "Hancom CSD 2005 Browser" fullword wide
    $s6  = ">.  All rights reserved." fullword wide
    $s7  = "Rich?c" fullword ascii
    $s8  = "There are no items to show in this view." fullword ascii
    $s9  = "HNC Install" fullword ascii
    $s10 = "Remove(&R)" fullword wide
    $s11 = "You have products installed listed below. Press the [Remove] button to remove selected product and install the product." fullword wide
    $s12 = "Install(&I)" fullword wide
    $s13 = " PLUS PDF)" fullword wide
    $s14 = "!Install Dialog Information(&A)..." fullword wide
    $s15 = "You have products installed listed below. Press the [Remove] button to remove selected product and install Haansoft Hangul 2007." wide
    $s16 = "You have products installed listed below. Press the [Remove] button to remove selected product and install Haansoft Slide 2007." fullword wide
    $s17 = "You have products installed listed below. Press the [Remove] button to remove selected product and install Haansoft Nexcel 2007." wide
    $s18 = "You have products installed listed below. Press the [Remove] button to remove selected product and install Haansoft Office 2007." wide
    $s19 = "You have selected to remove." fullword wide
    $s20 = "Remove Product?\"Preparing to install. Please wait." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}