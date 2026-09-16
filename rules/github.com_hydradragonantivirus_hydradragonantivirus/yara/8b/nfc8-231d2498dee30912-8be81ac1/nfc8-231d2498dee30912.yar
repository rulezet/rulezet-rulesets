rule nfc8_231d2498dee30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.231d2498dee30912"
    cluster         = "nfc8.231d2498dee30912"
    cluster_size    = "70"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "shedun androidos revo"
    md5_hashes      = "['e3adab56e6f88b8b9ac73985fef89d68192376b8','0f37c2d7c40695671ce25917ebc051e2cf99f237','2a6d8e62e1d374271cb227f7cb4071ad85f3904b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.231d2498dee30912"

  strings:
    $hex_string = { ba 29 0c 76 91 31 f8 5c 28 70 b8 0a 83 d5 41 b2 74 33 2e 8a 87 36 b7 2d 86 f2 e7 51 3a d6 ed d2 e3 73 1b 66 c6 b6 27 92 da 01 8d d8 99 b3 7a 0d 60 f4 9b 9d 5b 67 32 df e5 f6 59 7d 8b 78 5e 4b }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}