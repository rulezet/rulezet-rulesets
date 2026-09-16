rule j26d4_15a22b29cbd2d907 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26d4.15a22b29cbd2d907"
    cluster         = "j26d4.15a22b29cbd2d907"
    cluster_size    = "8"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "graftor malicious proxy"
    md5_hashes      = "['8c06d4ea2057352b5ff80ff89996973baf9f5a43','711127824f3ab1b1cbcd1307098376f0a394f2aa','d4513dadbbf4f1dbc8cb559c85c00134a31dca00']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26d4.15a22b29cbd2d907"

  strings:
    $hex_string = { 4b 50 46 46 ff 37 4e 4e 81 eb 88 23 01 00 5b 58 83 fb 00 0f 85 06 0a 00 00 0f 84 2d 0a 00 00 d3 fa 58 9b 1d 94 20 b9 81 b4 2c be 81 f2 2e 93 81 b2 3c bf cb d2 0a d7 47 f3 56 c6 6d ab 6b 22 12 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}