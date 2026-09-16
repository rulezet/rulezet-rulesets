rule o231d_711a92b9c2200b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o231d.711a92b9c2200b16"
    cluster         = "o231d.711a92b9c2200b16"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "fakeapp riskware clicker"
    md5_hashes      = "['c532f19c716a97d041e0f697e46af42d54abd890','139e91633b00486935bae025ac33a6adc98e6888','08f9e773f9acd2efc5259800d21491018579d0d8']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o231d.711a92b9c2200b16"

  strings:
    $hex_string = { a9 79 33 d2 f3 1c 63 e8 80 8d 9e 3d 87 65 2e 45 40 8b fd 46 26 52 03 04 12 a6 20 54 4a 16 ea 24 5e 97 e9 a8 09 b8 e7 a5 76 99 b3 53 cc 5d ab 35 f1 e1 22 fe 9b 0f ce f9 69 3b 4f af d1 55 c1 c0 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}