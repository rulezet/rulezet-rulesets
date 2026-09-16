rule k26bb_2992597983474912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.2992597983474912"
    cluster         = "k26bb.2992597983474912"
    cluster_size    = "62280"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installmonster bundler nsis"
    md5_hashes      = "['4c3c5d64b198a23ee38348de8fb86effe3f71349','e02a3b00ecf2babb3d5f013e8b896753ebb9a95e','d9266993ebadb51b1229e0601b18c72140fb24fd']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.2992597983474912"

  strings:
    $hex_string = { 4e 08 eb d6 8b 4c 24 04 a1 e8 2d 47 00 56 33 f6 83 f9 20 73 36 39 35 ec 2d 47 00 76 2e 8d 50 08 57 8b 02 a8 06 75 14 33 ff 47 d3 e7 85 7a fc 74 05 83 c8 01 eb 03 83 e0 fe 89 02 46 81 c2 20 40 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}