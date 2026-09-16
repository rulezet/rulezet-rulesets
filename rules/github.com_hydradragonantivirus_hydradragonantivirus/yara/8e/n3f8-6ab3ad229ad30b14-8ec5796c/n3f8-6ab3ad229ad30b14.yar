rule n3f8_6ab3ad229ad30b14 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.6ab3ad229ad30b14"
    cluster         = "n3f8.6ab3ad229ad30b14"
    cluster_size    = "546"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos smforw smssend"
    md5_hashes      = "['306761a7de778ec4db31e85d7bf8b6f4c08095e2','dfda1813ce0e4f4bb1698824e4c309aee6bbb0a0','3e5f8b90f00c3f4218180d4db9bab19b798867ac']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.6ab3ad229ad30b14"

  strings:
    $hex_string = { 35 98 14 00 07 58 07 09 54 99 05 01 07 5a 52 aa c5 00 6e 20 52 15 a9 00 0c 09 1f 09 95 00 5b 89 c4 00 d8 04 04 01 28 cd 1a 08 f9 02 22 09 26 03 07 9e 07 e9 07 ea 70 10 29 15 0a 00 1a 0a 11 08 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}