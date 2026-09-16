rule o26bb_6384a0b4dda30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.6384a0b4dda30912"
    cluster         = "o26bb.6384a0b4dda30912"
    cluster_size    = "12"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bundler malicious heuristic"
    md5_hashes      = "['6436c684d210da96e651022ad0895902d0437dfc','52d59b5d67ec8ef4987e5d7af16c8716e0c1cd5c','b4febe8431b1f32f6e9033d34ced12ae4ded2f86']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.6384a0b4dda30912"

  strings:
    $hex_string = { d9 c1 c3 0e 03 da 8b ce f7 d1 8b c3 23 c6 23 ca 0b c8 8b c2 81 c1 ed 14 5a 45 03 4d dc 03 f9 8b ca f7 d1 c1 cf 0c 23 cb 8d 96 05 e9 e3 a9 8b 75 b8 03 fb 23 c7 89 7d b0 0b c8 81 c6 f8 a3 ef fc }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}