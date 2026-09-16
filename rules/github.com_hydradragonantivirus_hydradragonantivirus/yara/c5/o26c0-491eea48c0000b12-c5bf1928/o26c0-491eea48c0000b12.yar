rule o26c0_491eea48c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.491eea48c0000b12"
    cluster         = "o26c0.491eea48c0000b12"
    cluster_size    = "138"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious genericrxer heuristic"
    md5_hashes      = "['7b31ba612f75d1c844edcbf00eea85600e2c8995','b845bbb499e65fed0496317ef57b491abdd4fb66','39e709e34748040c10738ef67e0c4e48d6882f5c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.491eea48c0000b12"

  strings:
    $hex_string = { f9 40 73 15 80 f9 20 73 06 0f a5 c2 d3 e0 c3 8b d0 33 c0 80 e1 1f d3 e2 c3 33 c0 33 d2 c3 cc 83 3d 54 4b 41 00 00 74 37 55 8b ec 83 ec 08 83 e4 f8 dd 1c 24 f2 0f 2c 04 24 c9 c3 83 3d 54 4b 41 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}