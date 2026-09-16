rule k26dd_139214f9c9000b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26dd.139214f9c9000b16"
    cluster         = "k26dd.139214f9c9000b16"
    cluster_size    = "4610"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "hackkms hacktool kmsactivator"
    md5_hashes      = "['99417c2b0aa25d3493fdd15ec9d62509cb9ab1d0','7761e076411fc5ea0ae3f05ca0b48f71c08e4e1b','2806c3e90a63f3a0d47fceefbaf7528b172de038']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26dd.139214f9c9000b16"

  strings:
    $hex_string = { 57 53 8d 45 fc 50 e8 d5 7e 00 00 85 c0 7c 2d 8b 45 fc 33 d2 8b cb f7 f1 3b c6 76 20 8b d7 89 45 f8 8b 4d 0c 8b 7d 08 8d 72 0a 33 c0 f3 a6 75 05 8b 02 89 45 f4 03 d3 ff 4d f8 75 e5 68 5f 44 49 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}