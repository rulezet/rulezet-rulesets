rule k26bb_29366de3dec34916 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.29366de3dec34916"
    cluster         = "k26bb.29366de3dec34916"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installcore unwanted core"
    md5_hashes      = "['d3a762d722325eee886c4f62fe9e0fb8f6374730','e3a76a7ea7402ec8907d038cda7c74c365f68929','3286482337524c66a5f4ec715115f03321cbff03']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.29366de3dec34916"

  strings:
    $hex_string = { 2c b1 af 5d ee cd 4b c5 d9 4c 99 89 3f 2b 07 08 35 4d 17 c9 da dd 7d 56 50 65 04 cb 83 f9 c6 9b c1 c7 24 3c be 7b 01 f3 e7 ca 88 0d a9 25 86 87 e1 63 96 95 cc aa 9a 5b b7 1b ad ec d7 5e 6a 8a }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}