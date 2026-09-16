rule k26bb_194e79e12ec7e79a {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.194e79e12ec7e79a"
    cluster         = "k26bb.194e79e12ec7e79a"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installcore malicious unwanted"
    md5_hashes      = "['0cdee7b9bde0a69a283c4cf0dc732e446a449ccd','3d63e1fe4eb912438eaedee43670b2958f69ed02','76770aea5080d87ec19e693a4a4a171eee739553']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.194e79e12ec7e79a"

  strings:
    $hex_string = { b0 2d f7 da eb 06 0a e4 74 03 8a c4 aa 92 50 8b dc 33 d2 f7 35 0c 5d 40 00 80 c2 30 88 13 43 49 0b c0 75 ed 0b c9 7f e9 4b 8a 03 aa 3b dc 75 f8 58 c3 e8 1c ff ff ff 8b 55 08 83 fa 12 72 05 ba }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}