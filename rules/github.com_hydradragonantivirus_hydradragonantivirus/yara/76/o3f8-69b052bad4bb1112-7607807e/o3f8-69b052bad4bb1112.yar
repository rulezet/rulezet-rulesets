rule o3f8_69b052bad4bb1112 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o3f8.69b052bad4bb1112"
    cluster         = "o3f8.69b052bad4bb1112"
    cluster_size    = "99"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "clicker androidos apprisk"
    md5_hashes      = "['9529254eaac41ed0865864c0a4f6e3aba5a91b3b','fc9a2d49a04105dfb3193cb0fb4454b29f3dd410','93f6da3eb0d9a6263882c58ad9c0763906466bc5']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o3f8.69b052bad4bb1112"

  strings:
    $hex_string = { 8e 22 52 73 46 00 52 74 47 00 70 40 7a 00 21 43 07 10 28 e1 0d 01 54 72 44 00 22 03 2c 00 52 74 46 00 52 75 47 00 70 40 7a 00 63 54 6e 10 58 5c 01 00 0c 01 71 20 9b 00 13 00 0c 01 72 20 e2 5e }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}