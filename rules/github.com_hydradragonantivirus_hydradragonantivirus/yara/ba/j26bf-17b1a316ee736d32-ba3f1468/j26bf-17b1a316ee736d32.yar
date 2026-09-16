rule j26bf_17b1a316ee736d32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26bf.17b1a316ee736d32"
    cluster         = "j26bf.17b1a316ee736d32"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "grwtpstealer stealer malicious"
    md5_hashes      = "['ea2bf6be81bb1dd8312eb001f56cc499b52c5743','516b2618625f833cf0eea0d1a59ffc01f8c4ae83','8e1cd372b18cebddd9b845b21fdf80dbe2c0d40c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26bf.17b1a316ee736d32"

  strings:
    $hex_string = { 0a 16 fe 01 13 0b 11 0b 2d 0c 00 17 80 01 00 00 04 dd a9 04 00 00 72 a8 03 00 70 72 f8 03 00 70 28 06 00 00 06 6f 0f 00 00 0a 72 1e 02 00 70 6f 10 00 00 0a 16 fe 01 13 0b 11 0b 2d 0c 00 17 80 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}