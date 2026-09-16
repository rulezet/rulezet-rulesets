rule nfc8_3946a990d9eb0b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.3946a990d9eb0b16"
    cluster         = "nfc8.3946a990d9eb0b16"
    cluster_size    = "13"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "svpeng slocker koler"
    md5_hashes      = "['947e98010cc3dc0724cbf7c827e2e5428cf2913d','b1ba1575ed6e06d2f30f1bc07e3028f5de26464f','02890d0a890f10392b3787dc439eebdc85681ec6']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.3946a990d9eb0b16"

  strings:
    $hex_string = { 15 c5 4b 0d be bc 9c ca dd 01 80 46 ad d0 d6 cb 26 0e 16 00 28 07 d1 36 8a 2e fc bd 7f bd 73 6d 04 6b 50 1d 42 08 90 ee 09 ec 3f 31 a2 2d ed e6 1c da fe 4d 61 8b 7c a1 f5 a9 19 13 94 fb 84 b0 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}