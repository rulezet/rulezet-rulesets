rule nfc8_529a4069c2cb4e5b {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.529a4069c2cb4e5b"
    cluster         = "nfc8.529a4069c2cb4e5b"
    cluster_size    = "9"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos koler boogr"
    md5_hashes      = "['436a80ce9413d125c63576b7988af02b30b9e37a','a85f4cfc3f3d7927a51a5f7aa3cb5ae0837bc241','b118d50c15a631a3330360331fe8ae408635dc46']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.529a4069c2cb4e5b"

  strings:
    $hex_string = { ba 68 d6 5d b1 53 ca 28 85 17 42 80 00 e8 d7 67 6d bc f0 e2 64 50 d4 f7 c0 73 ce 33 ec 41 e5 7b c8 ab 20 92 03 c4 07 93 39 ef cd c5 ad 77 dc 8e 65 cb 7e 43 49 22 e1 9b 29 90 b0 98 01 db b6 7d }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}