rule p26bb_3158dac2c8000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26bb.3158dac2c8000b32"
    cluster         = "p26bb.3158dac2c8000b32"
    cluster_size    = "2879"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dropped crypt genericr"
    md5_hashes      = "['c1f11e32d2fe00e2f757cd98affc69de326e4879','2fd773753a801d3f77e1aa88b8820a0086f098af','f354ab93e2412763a8572866582c93ed28adb3d8']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26bb.3158dac2c8000b32"

  strings:
    $hex_string = { ea 26 fd 44 9d c8 ac 52 e8 25 5e 80 ec f8 81 88 33 43 1a 40 dc eb 34 cf 18 f6 11 b8 38 95 fb ab 28 17 76 c6 d4 d0 42 12 5f 1b b0 da e0 3e 10 5d f7 f3 7a 29 54 7b c0 13 04 8d 47 7c 2b 2d 83 7f }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}