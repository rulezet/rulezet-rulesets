rule qfc8_011938c1c4000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=qfc8.011938c1c4000b32"
    cluster         = "qfc8.011938c1c4000b32"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos highconfidence jiagu"
    md5_hashes      = "['a85c0912f1d2fdf550a561cb5c215e9ccc310a85','bb6835a98b7f6b486b820a603a4ccd2886aa52f4','39ef6f166649ebb0b4f415f3a10d986c3c0eb9d8']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=qfc8.011938c1c4000b32"

  strings:
    $hex_string = { 1b 4e 2f d1 7e 1a cb f0 d5 6c d7 17 87 b8 27 5b 6f d6 67 ed ca 86 7d b5 de c7 3f a0 57 fe 01 25 92 a1 11 bb 0e 82 8f 0b b6 63 df b7 ef f4 c0 53 3e 9b c4 e3 ab 4f a7 3b d8 04 5e 76 cc 51 77 4c }

  condition:
    filesize > 16777216 and filesize < 67108864
    and $hex_string
}