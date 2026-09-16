rule k26bb_193c79e159b2f316 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.193c79e159b2f316"
    cluster         = "k26bb.193c79e159b2f316"
    cluster_size    = "46"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installcore malicious unwanted"
    md5_hashes      = "['a34fed97beaaf91b6db7e0006aa962467bd13d87','bd27e568210b3243d0314e47ce7eaf23c96a6b60','1422b6ccb81f3dc027f4b09c3a69c32a19cbea55']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.193c79e159b2f316"

  strings:
    $hex_string = { 61 20 69 73 20 63 6f 72 72 75 70 74 65 64 20 28 25 64 29 00 00 53 83 c4 f8 8b d8 89 1c 24 c6 44 24 04 0b 54 6a 00 b9 18 7e 40 00 b2 01 b8 c8 77 40 00 e8 be da ff ff e8 a9 b0 ff ff 59 5a 5b c3 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}