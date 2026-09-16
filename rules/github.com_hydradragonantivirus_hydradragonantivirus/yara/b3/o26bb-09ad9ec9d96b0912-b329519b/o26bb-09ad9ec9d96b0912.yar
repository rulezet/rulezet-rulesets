rule o26bb_09ad9ec9d96b0912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.09ad9ec9d96b0912"
    cluster         = "o26bb.09ad9ec9d96b0912"
    cluster_size    = "28"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious softcnapp"
    md5_hashes      = "['d1dcd0aaf184bf88b3aa3abc84f1d8f44d290247','be3d186ff69edab7b6449b0749ba5c73d4ffce25','4297c7f30243a2afde2d8f216ad45a6a363c4661']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.09ad9ec9d96b0912"

  strings:
    $hex_string = { 3b 5d dc 1b c9 23 4d d8 2b 4d dc 03 cb 8a 0c 11 88 0c 13 43 8b 55 e4 42 89 5d ec 83 7d f0 07 89 55 e4 1b f6 83 e6 fe 83 c6 0b 89 75 f0 e9 35 08 00 00 2b f9 2b c1 8b ce c1 e9 05 2b f1 66 89 33 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}