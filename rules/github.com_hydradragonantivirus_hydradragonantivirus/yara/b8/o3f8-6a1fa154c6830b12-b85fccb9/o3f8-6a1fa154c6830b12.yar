rule o3f8_6a1fa154c6830b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o3f8.6a1fa154c6830b12"
    cluster         = "o3f8.6a1fa154c6830b12"
    cluster_size    = "19"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos apprisk clicker"
    md5_hashes      = "['cfb53768fd931951e9558261614f37625c652416','cc4b237a1f2f858051c469d8b9b3d8e131644ccb','d7a037814b7764ffea2daadb83c97c92d2f447d2']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o3f8.6a1fa154c6830b12"

  strings:
    $hex_string = { 00 40 c0 80 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}