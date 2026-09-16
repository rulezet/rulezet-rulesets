rule o26bb_4162fcc148000912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.4162fcc148000912"
    cluster         = "o26bb.4162fcc148000912"
    cluster_size    = "7"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "ibryte installer optimum"
    md5_hashes      = "['68ae456bc8fe8e840c1fb96978c465d4b7e7a2d9','eb4c5c6e84d9d8ded0546ad01c5541cda2446cdc','94013f2af7ed2f0982824d013cbbd3e61112a649']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.4162fcc148000912"

  strings:
    $hex_string = { 43 10 76 54 ce ef 18 b1 2d b9 6b 8f 7f f9 de 93 cb 14 aa 80 d2 2b d3 03 97 f5 e4 66 fd ba df bf 26 b6 79 a2 b7 ed 57 5d b8 9b fa 25 cd 1a d7 ee f7 53 3b ff 6f a7 a4 c9 b4 42 a9 34 a3 24 95 2c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}