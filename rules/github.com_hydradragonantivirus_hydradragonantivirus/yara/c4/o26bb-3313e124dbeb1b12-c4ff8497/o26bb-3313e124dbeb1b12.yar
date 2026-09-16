rule o26bb_3313e124dbeb1b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.3313e124dbeb1b12"
    cluster         = "o26bb.3313e124dbeb1b12"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "webalta malicious toolbar"
    md5_hashes      = "['c443837a69a93f28da25dc5c81cca3224921a1c7','f5474da1cc3cd11f69ebbbd1bb47dd6da5646366','5036755c3b93f0dfcb939e9184885b5ac3fb33dc']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.3313e124dbeb1b12"

  strings:
    $hex_string = { da eb 06 08 e4 74 03 88 e0 aa 92 50 89 e3 31 d2 f7 b6 60 81 51 00 80 c2 30 88 13 43 49 09 c0 75 ed 09 c9 7f e9 4b 8a 03 aa 39 e3 75 f8 58 5e c3 90 55 8b ec 83 c4 d4 57 56 53 89 45 fc a0 3b c7 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}