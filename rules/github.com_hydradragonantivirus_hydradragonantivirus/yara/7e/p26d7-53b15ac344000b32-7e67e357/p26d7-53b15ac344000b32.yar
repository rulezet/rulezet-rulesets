rule p26d7_53b15ac344000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26d7.53b15ac344000b32"
    cluster         = "p26d7.53b15ac344000b32"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installmonster symmi installmonstr"
    md5_hashes      = "['fdbbdf03a9893b726e2158298a405e67fb4afbcf','94e4b53a0d1f4808325ec4e5cba78e08dc075b4d','d982b3f79f197cba42c3fc50518de0a92578b626']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26d7.53b15ac344000b32"

  strings:
    $hex_string = { 85 23 78 03 f8 ed 7d 63 8d 55 7b 4d da 02 3a 7c fa 07 0f 87 93 24 d1 4c e8 e0 88 90 0a 49 47 ca 6d ec d6 0d 8b 26 21 45 01 db e4 36 c2 13 08 0c eb 44 1a 04 dc 06 bf 20 c9 1b 76 ef de 5d bc 2f }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}