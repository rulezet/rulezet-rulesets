rule o26c0_599aa254db9b1912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.599aa254db9b1912"
    cluster         = "o26c0.599aa254db9b1912"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "graftor kryptik malicious"
    md5_hashes      = "['78cdcbf0a26ffd0d4eb758136003158bbea6d90d','4c8a8837be7ba71d112dc44340fb498706951be4','1ae4c30d6981a0bc27a541f8cf8d3be43ac03b25']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.599aa254db9b1912"

  strings:
    $hex_string = { d4 c6 da 7b 65 75 89 76 99 a3 43 b2 1f e7 35 f2 72 4b cc 82 ae e0 46 3d 9a 50 7d cb 5a 79 db 90 2a 6e 32 4f e4 41 e2 54 8d ef 33 07 e6 e5 f9 ac 06 6f 7c 93 ed d3 27 3a 24 04 c7 47 5b 2f 19 18 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}