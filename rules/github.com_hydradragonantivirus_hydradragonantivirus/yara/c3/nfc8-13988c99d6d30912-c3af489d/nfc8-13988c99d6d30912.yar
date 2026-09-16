rule nfc8_13988c99d6d30912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.13988c99d6d30912"
    cluster         = "nfc8.13988c99d6d30912"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "gthyv ransom adlibrary"
    md5_hashes      = "['905e2e37f838cb554c938d25c773dfdb95a1a85b','baa204c70ba6c1c8ae99fa01dda65ae742942339','2db399c5134723093c65ad4f7b1a89f25801d29b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.13988c99d6d30912"

  strings:
    $hex_string = { d9 61 5d 8d 9c ed 46 c1 9a 89 39 f7 28 51 67 f6 10 fd 35 1d 73 9d 0e 25 b9 3e 6c 40 1c 3b 82 eb d6 6b 50 c3 41 f2 33 52 95 19 96 ab 22 bc 1f 23 24 15 3d 8a 69 e6 f9 b8 a4 7d b6 86 a3 e8 0a 78 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}