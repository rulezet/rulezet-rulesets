rule k26bb_65d53a6b8ec10b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.65d53a6b8ec10b12"
    cluster         = "k26bb.65d53a6b8ec10b12"
    cluster_size    = "461"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious aajd highconfidence"
    md5_hashes      = "['52a1300815edb3f4592646393b3b6399c850fca6','449f233415ce53da426e8563b5e76c01d42f8fd0','d36ac77a6865ca1ccaf78db07c4ab3aa4136f443']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.65d53a6b8ec10b12"

  strings:
    $hex_string = { d0 80 e2 01 f6 da 1b d2 81 e2 20 83 b8 ed d1 e8 33 c2 4e 75 ea 89 04 8d 28 19 43 00 41 81 f9 00 01 00 00 7c d5 8b 54 24 10 8b 44 24 08 85 d2 f7 d0 76 23 8b 4c 24 0c 57 0f b6 39 8b f0 81 e6 ff }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}