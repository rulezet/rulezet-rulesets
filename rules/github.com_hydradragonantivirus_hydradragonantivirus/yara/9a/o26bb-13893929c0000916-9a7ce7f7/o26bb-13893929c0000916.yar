rule o26bb_13893929c0000916 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.13893929c0000916"
    cluster         = "o26bb.13893929c0000916"
    cluster_size    = "526"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "downloadsponsor malicious unwanted"
    md5_hashes      = "['3d15536e9d98545c9377801e748b807069a46cd1','a0103a8260683b185c7879a01c2fe71aee169a31','7b37dad261c4913c942f554c7e1b519aa38f1c51']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.13893929c0000916"

  strings:
    $hex_string = { 1b 10 49 96 51 5a 5d 4e 32 16 4d 7f 22 dc 85 6b 82 ec 1a 75 15 72 b0 d4 5e 94 e6 80 55 b2 3c 5b c1 86 d1 c6 26 c2 cf 27 ad ea 34 18 0c b6 44 2b 1c 84 f0 d7 bc a3 17 8b 25 13 08 81 c9 9c cc 69 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}