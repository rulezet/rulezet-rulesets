rule o26bb_3b9d5259bb230b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.3b9d5259bb230b12"
    cluster         = "o26bb.3b9d5259bb230b12"
    cluster_size    = "7"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kuaizip kuzitui malicious"
    md5_hashes      = "['273c2328e69254b39c235c3f519bb3a2a4dd669f','6626e2378403b3a2d5bbd7471d3804745136e904','388a746a91abc6fcb4c5901c69f0700fa11cfbb4']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.3b9d5259bb230b12"

  strings:
    $hex_string = { cb e8 7e a3 fe ff 83 c4 08 eb 0f 8b 4c 24 30 85 c9 74 07 89 48 10 c6 40 01 fe 85 f6 74 32 80 7f 13 08 73 2c 33 c0 8d 8f 94 00 00 00 38 47 19 76 11 39 71 0c 74 56 0f b6 57 19 40 83 c1 14 3b c2 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}