rule o26bb_594e4e6a9ee30932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.594e4e6a9ee30932"
    cluster         = "o26bb.594e4e6a9ee30932"
    cluster_size    = "225"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dealply malicious btlfk"
    md5_hashes      = "['69120c7ecb938bfb57c41fbd92640cbfbf5546da','fb0b9870b424c14698ad4715278c4461f1be9f47','89e504f53bc0af1f28b07896ac9d718eb29e9523']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.594e4e6a9ee30932"

  strings:
    $hex_string = { cb 88 08 42 40 0f b6 c9 92 e8 09 d0 ff ff 5b c3 8d 40 00 55 8b ec 56 57 89 c6 8b 7d 08 31 c0 0a 06 74 2b 85 d2 7e 18 39 c2 7f 1b 29 d0 40 85 c9 7c 14 39 c1 7f 14 01 d6 88 0f 47 f3 a4 eb 11 ba }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}