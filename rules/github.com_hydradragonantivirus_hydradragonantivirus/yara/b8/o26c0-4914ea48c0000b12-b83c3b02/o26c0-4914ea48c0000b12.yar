rule o26c0_4914ea48c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.4914ea48c0000b12"
    cluster         = "o26c0.4914ea48c0000b12"
    cluster_size    = "8"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious heuristic amlioos"
    md5_hashes      = "['30bf12ded205c2155169de4b37e2087e74126896','5e20476f4601e4b68bdbf6de7c307b906485b9ef','5a6996b9dd0b0d87fc10b6695b5e754e38c2f3a4']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.4914ea48c0000b12"

  strings:
    $hex_string = { 8d 46 18 57 50 e8 8e c8 ff ff 89 5e 04 83 c4 0c 33 db 89 be 1c 02 00 00 43 39 5d e8 76 51 80 7d ee 00 8d 45 ee 74 21 8a 48 01 84 c9 74 1a 0f b6 d1 0f b6 08 eb 06 80 4c 0e 19 04 41 3b ca 76 f6 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}