rule i26c0_69bd33a9c2000912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i26c0.69bd33a9c2000912"
    cluster         = "i26c0.69bd33a9c2000912"
    cluster_size    = "226"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "zusy malicious exad"
    md5_hashes      = "['5b714a5ccb57421650c14dc8b19bbefeb4146c50','97ca4068dbbfdab7a1e1c007bf0927f4a5c94389','afe29ec433a7e0f7f14bb7fbfd9b8870534df35e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i26c0.69bd33a9c2000912"

  strings:
    $hex_string = { fa 74 46 49 75 d6 c9 c2 08 00 25 30 38 78 0a 00 53 75 63 63 65 73 0a 00 5f 25 73 2e 65 78 65 00 31 c0 eb 07 eb 8b 64 24 08 eb 03 eb f8 74 64 8f 00 eb 06 e9 83 c4 04 eb 03 eb f9 eb 61 68 6f 02 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}