rule p26bb_29976a48c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26bb.29976a48c0000b12"
    cluster         = "p26bb.29976a48c0000b12"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious cheatengine hacktool"
    md5_hashes      = "['c1e0692c6a3d66ecd62ebac5bcc0edb8ec6570b2','522b97b2f154381f0e9e03b7cbb9c366f54af10a','9ecf528e6ee4ff607b4e247b2c651991ef897499']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26bb.29976a48c0000b12"

  strings:
    $hex_string = { 01 eb 27 3b 7d f0 7f d3 c6 45 f4 00 e8 36 53 ff ff a1 b0 26 43 00 e8 ec c4 ff ff 58 85 c0 74 0f 83 f8 02 74 0a e8 4d 54 ff ff 58 6a 02 eb dd 8a 45 f4 5f 5e 5b c9 c3 53 56 57 8d 64 24 fc 89 04 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}