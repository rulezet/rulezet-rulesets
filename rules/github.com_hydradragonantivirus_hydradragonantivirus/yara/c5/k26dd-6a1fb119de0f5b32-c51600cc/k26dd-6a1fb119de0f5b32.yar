rule k26dd_6a1fb119de0f5b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26dd.6a1fb119de0f5b32"
    cluster         = "k26dd.6a1fb119de0f5b32"
    cluster_size    = "72"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "yontoo yotoon adplugin"
    md5_hashes      = "['73f7584a9d4fb535e892e2b7d2cdf6b4b2aad71c','a5c6abf1edd80d1a8514141e7b9d42b88d766d6d','a9bee7fd3df37c4807c8c2c8a5740c253a5d7cdb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26dd.6a1fb119de0f5b32"

  strings:
    $hex_string = { 4e 08 89 4f 08 8a 40 30 04 02 0f b6 c0 53 50 ff 15 28 91 01 00 8b d8 33 d2 3b da 75 05 8a 55 fc eb c9 b9 4c 44 01 00 8b c1 85 c0 8b 43 60 74 0f 83 e8 24 89 48 1c 89 78 20 c6 40 03 e0 eb 0c 83 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}