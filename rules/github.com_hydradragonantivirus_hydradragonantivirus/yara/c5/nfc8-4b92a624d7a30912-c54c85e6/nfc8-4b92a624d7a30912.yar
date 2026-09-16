rule nfc8_4b92a624d7a30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.4b92a624d7a30912"
    cluster         = "nfc8.4b92a624d7a30912"
    cluster_size    = "145"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dedc nymaim kryptik"
    md5_hashes      = "['cac7737e372673fab20caecc0c2f0f1a3c4df7e9','5e5f56536d2e415e9994b0df502cd34121c66255','2e562afd2643a4423ddbf311bb7e59d2d278ba6f']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.4b92a624d7a30912"

  strings:
    $hex_string = { 0b 84 28 8e e7 2a 1b d5 6a 0c 0e a2 5c 0a 94 eb 9d a7 49 af d7 ed 64 c2 78 40 8b c6 f1 98 12 37 a9 f6 77 2e 7f d6 6c 7d 24 81 08 1c 3c aa 3a d6 dc c7 fe a0 ee ec 58 e8 e3 47 3b 82 4a 44 c1 13 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}