rule o26bb_17d25999c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.17d25999c2200b12"
    cluster         = "o26bb.17d25999c2200b12"
    cluster_size    = "37"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "gamehack malicious unsafe"
    md5_hashes      = "['d2aef40fb7726bd3fd169d60114a681519f5553e','d63a15c72ab948240345cb6a75c6f2392251291d','3a74eefb937ad98ceda962494dc7f6cc27d64b4c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.17d25999c2200b12"

  strings:
    $hex_string = { 89 7c 24 50 4c 63 fd 4f 8d 24 bf 49 c1 e7 04 0f 29 74 24 40 49 c1 e4 03 49 83 c7 08 4b 8b 04 2f 4c 2b f0 3b ef 7d 42 0f 57 f6 85 ed 79 21 33 db 85 ff 7e 39 0f 1f 44 00 00 8b d3 48 8b ce e8 b6 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}