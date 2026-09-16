rule o26bb_4562d1029b6f4932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.4562d1029b6f4932"
    cluster         = "o26bb.4562d1029b6f4932"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious asvcs engine"
    md5_hashes      = "['a792795de9a105ffba0c3c9479256ba09d20938f','7301e5ba9d2bb6045574d54ce8f2113c5a10fda2','f3252094af75b97d780c0f05b06c073aa9d5b5da']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.4562d1029b6f4932"

  strings:
    $hex_string = { d1 f8 88 0c 10 3b f7 7c c0 b0 01 5e 5f 5b 8b e5 5d c3 32 c0 eb f5 55 8b ec 51 53 56 57 8b f9 8b f2 57 e8 cf d4 fb ff 83 26 00 59 33 c9 c7 45 fc 30 00 00 00 41 8d 50 ff 33 db 85 d2 78 3f 0f b7 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}