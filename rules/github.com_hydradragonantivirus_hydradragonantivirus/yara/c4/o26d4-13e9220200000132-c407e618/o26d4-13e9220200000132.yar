rule o26d4_13e9220200000132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d4.13e9220200000132"
    cluster         = "o26d4.13e9220200000132"
    cluster_size    = "3133"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious adposhel possible"
    md5_hashes      = "['84b30c782593a455efdb0476ad07e25390c97621','4a4e23cb1065cc97b6ee3abaa681becf7b736a5b','53e91c093772a4360800feaff901779310b470c0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d4.13e9220200000132"

  strings:
    $hex_string = { fe 27 05 cb 00 00 05 cb 00 00 f6 2b 00 00 f6 2b 00 00 f8 0b fe 27 a1 d5 00 00 a1 d5 00 00 3f 69 00 00 3f 69 00 00 f8 0b fe 27 1a b2 00 00 1a b2 00 00 c2 f1 00 00 c2 f1 00 00 f8 0b fe 27 4f 36 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}