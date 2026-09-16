rule o26bb_07c294e1c6000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.07c294e1c6000b12"
    cluster         = "o26bb.07c294e1c6000b12"
    cluster_size    = "95"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "gamehack malicious filerepmalware"
    md5_hashes      = "['e228344a3e6dd901a380c2838719eed6a376ea60','75a881a26c7c4d9194bdf99f0595342c3eb95688','7a93160285bdef2e8d4e7500430b6c692ce678e9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.07c294e1c6000b12"

  strings:
    $hex_string = { 45 01 8b cf 2b ca 41 53 33 db d1 e9 3b fa 1b ff f7 d7 23 f9 76 11 8d 64 24 00 8a 0a 8d 52 02 88 08 43 40 3b df 72 f3 c6 46 0b 08 5b eb 39 80 f9 10 0f 85 fc 00 00 00 83 7c 24 18 00 74 05 8d 55 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}