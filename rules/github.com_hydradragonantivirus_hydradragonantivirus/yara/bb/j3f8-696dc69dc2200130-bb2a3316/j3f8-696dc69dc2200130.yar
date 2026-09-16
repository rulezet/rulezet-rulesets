rule j3f8_696dc69dc2200130 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j3f8.696dc69dc2200130"
    cluster         = "j3f8.696dc69dc2200130"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "banker adlibrary androidos"
    md5_hashes      = "['f40ca9613141db3dc6a1a4f867ed1b889fd37789','5060c5343703e210f604b04558aaa4f34b87eef3','49c5d6bceebfc304e48850a382d4985e5af8896f']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j3f8.696dc69dc2200130"

  strings:
    $hex_string = { 76 69 74 79 3b 00 19 4c 61 6e 64 72 6f 69 64 2f 61 70 70 2f 41 70 70 6c 69 63 61 74 69 6f 6e 3b 00 1b 4c 61 6e 64 72 6f 69 64 2f 61 70 70 2f 49 6e 74 65 6e 74 53 65 72 76 69 63 65 3b 00 15 4c }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}