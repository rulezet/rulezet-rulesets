rule o26d4_19e916c2c8001132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d4.19e916c2c8001132"
    cluster         = "o26d4.19e916c2c8001132"
    cluster_size    = "9016"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bitminer coinminer possible"
    md5_hashes      = "['38fb25c1fc403de182285a91073719a0486c0884','30cb41c9a2e86143d8c5b5f5373938c57617b35c','e95adb5ed36c493bac45d2a7dcfb3937525e2fd7']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d4.19e916c2c8001132"

  strings:
    $hex_string = { 03 10 b6 f0 03 00 9a f3 03 10 a5 f3 03 10 d1 f7 03 10 ef f7 03 10 d8 fb 03 10 f6 fd 03 10 e6 00 04 10 a0 09 04 00 df 0a 04 10 81 11 04 00 f9 14 04 10 8b 15 04 10 b9 15 04 10 c4 18 04 00 c1 1b }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}