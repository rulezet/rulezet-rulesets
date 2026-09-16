rule k26d4_09e11cc9c8001132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26d4.09e11cc9c8001132"
    cluster         = "k26d4.09e11cc9c8001132"
    cluster_size    = "34"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "goopdate riskware alteredsoftware"
    md5_hashes      = "['a80e50498ba94241baf0d56a059eb9128fc48e67','660f732b5e3f5ab0fa224e6fd1bf579008026b3f','2806a0e4f67a18d026cbc0a3bbf1e38338969334']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26d4.09e11cc9c8001132"

  strings:
    $hex_string = { 49 ff a2 b3 9d ff fc f3 fe ff e4 fa df ff 7c da 65 ff 60 d1 44 ff 69 d4 4f ff 53 ce 35 ff 3f cd 1c ff 33 7e 13 e5 23 46 0a 13 9f bc 8c 00 8f b1 79 94 51 c1 32 ff 58 d2 3c ff 76 d8 5e ff 75 d7 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}