rule nfc8_611c96b9caa00b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.611c96b9caa00b12"
    cluster         = "nfc8.611c96b9caa00b12"
    cluster_size    = "651"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "obfus banker androidos"
    md5_hashes      = "['362d65afff838fa8a66837945a11bedd93e16f2b','d3ef79da836b4a43bfa091adc3ded597bc4b232e','7ae988c1ba957b8cf70a941c163a8c35964309ae']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.611c96b9caa00b12"

  strings:
    $hex_string = { e2 f6 7c e1 05 1e 58 15 c2 cc 9b 3c 06 fa 19 9e 3d 77 ee ee e3 70 5f cf da d3 c1 8e 41 7b 3b dd bc c3 e7 db f1 cb 8a 01 c5 87 40 4f d4 0f f0 7e 5d be eb fd 86 ab 27 b2 9f 53 1c 6b 6f cd a0 f3 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}