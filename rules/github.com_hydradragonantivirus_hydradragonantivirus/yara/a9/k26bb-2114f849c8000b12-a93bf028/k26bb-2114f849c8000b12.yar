rule k26bb_2114f849c8000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.2114f849c8000b12"
    cluster         = "k26bb.2114f849c8000b12"
    cluster_size    = "150"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "backdoor darkkomet malicious"
    md5_hashes      = "['22c1218125f095baa4bf7b8030e08dc876cff54f','e2298d347b069a7cbdd6bacbabed37dad43fbba2','d3f474b10320c0435eca1d81216810fed9d7c248']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.2114f849c8000b12"

  strings:
    $hex_string = { 14 0b d3 e0 3b 55 f4 73 1e 8d 74 55 a4 8b ff 0f b7 3e 2b c7 85 c0 7e 0c 42 41 83 c6 02 03 c0 3b 55 f4 72 eb 8b 75 dc b8 01 00 00 00 8b f8 d3 e7 01 7d e8 89 7d d0 39 45 08 75 0d 81 7d e8 b0 05 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}