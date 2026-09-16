rule nfc8_1b9f6a48c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.1b9f6a48c0000b12"
    cluster         = "nfc8.1b9f6a48c0000b12"
    cluster_size    = "14"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos smssend smsagent"
    md5_hashes      = "['fe04b9dd0b19ab55d7fdb45bfc9ba43e20d5d7f0','770e7da1f131ff7a9ce8265554efc192ac080e48','0ecb0a7e4ce9a307ea962bc32c365f8a56c9136b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.1b9f6a48c0000b12"

  strings:
    $hex_string = { 94 ce b4 c6 aa 24 35 fb d2 46 7a 87 a2 e8 6b 37 df 5c a5 95 e7 8d 27 51 58 81 71 d3 39 5f 76 c7 a0 b5 60 64 75 05 03 43 0e db f7 7d 11 4f ec d9 8a d7 bf 7a 23 de f8 ba f5 a8 54 06 3b 5d 2c ca }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}