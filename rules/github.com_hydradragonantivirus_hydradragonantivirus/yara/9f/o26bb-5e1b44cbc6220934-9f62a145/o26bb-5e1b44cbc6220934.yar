rule o26bb_5e1b44cbc6220934 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.5e1b44cbc6220934"
    cluster         = "o26bb.5e1b44cbc6220934"
    cluster_size    = "63"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dangeroussig eksktak icloader"
    md5_hashes      = "['dea6884208b837d4a820b5208966d72fa7ed475e','027ed3d7261a6d2bb16edc3b2fbc41cdb37f1747','b97a2a66ac9f26faef814f5b12d5acfca1f6099a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.5e1b44cbc6220934"

  strings:
    $hex_string = { 21 36 31 31 31 4e 41 41 41 68 50 50 50 7f 5f 5f 5f 95 6c 6c 6c ab 79 79 79 be 84 84 84 cc 8d 8d 8d d6 94 94 94 dc 9a 9a 9a e5 9f 9f 9f ec a3 a3 a3 ef a5 a5 a5 f2 a8 a8 a8 f4 a9 a9 a9 f6 83 aa }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}