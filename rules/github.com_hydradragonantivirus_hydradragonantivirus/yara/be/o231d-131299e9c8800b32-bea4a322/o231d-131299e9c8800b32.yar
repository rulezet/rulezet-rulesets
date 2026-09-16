rule o231d_131299e9c8800b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o231d.131299e9c8800b32"
    cluster         = "o231d.131299e9c8800b32"
    cluster_size    = "11"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smspay riskware androidos"
    md5_hashes      = "['430e6badcff00429e827cf6eacde4a8d196cb9f0','b27d6cc4c95d7fd823dfc233dc12fb3da7226d5c','83eb1996a6ac17250169f02370ac523706765266']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o231d.131299e9c8800b32"

  strings:
    $hex_string = { 66 33 bb 38 c6 15 1e f2 9e 1f c4 2b 23 0f 28 4c 45 ea d0 86 be 8c 64 12 f3 58 c5 01 4e f1 84 f7 44 2c ab d6 49 42 36 4a 52 8b 8e f4 63 34 b3 59 cb 41 2e 71 9b d7 fc 24 5a 90 ba 22 03 b9 29 47 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}