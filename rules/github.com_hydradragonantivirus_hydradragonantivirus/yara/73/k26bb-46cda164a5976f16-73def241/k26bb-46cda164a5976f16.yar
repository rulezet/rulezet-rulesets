rule k26bb_46cda164a5976f16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.46cda164a5976f16"
    cluster         = "k26bb.46cda164a5976f16"
    cluster_size    = "9"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "explorerhijack emhuei malicious"
    md5_hashes      = "['52c4fa81731eec277645296543a9bb7199658643','0b7520e6905c562bc01a81ea8330935499e5ea71','b668c16cbc1e13059f05907e20d048bdc72808dc']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.46cda164a5976f16"

  strings:
    $hex_string = { 01 c3 51 b8 d3 4d 62 10 f7 e1 53 55 56 57 8b fa c1 ef 06 8b c7 69 c0 e8 03 00 00 2b c8 74 03 83 c7 01 8b 2d cc 50 40 00 32 db 88 5c 24 13 33 f6 8b ff 80 7c 24 13 00 75 2c 3b f7 73 28 e8 30 fd }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}