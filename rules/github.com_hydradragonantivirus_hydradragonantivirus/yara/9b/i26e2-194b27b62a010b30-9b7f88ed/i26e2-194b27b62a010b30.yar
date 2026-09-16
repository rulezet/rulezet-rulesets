rule i26e2_194b27b62a010b30 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i26e2.194b27b62a010b30"
    cluster         = "i26e2.194b27b62a010b30"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "pantera fdfd bondat"
    md5_hashes      = "['19ce68bbb00406bbe2d2c06e3b7198298f4f250d','88cea2f8f2b42ac75041f04d298dd21f8e7d9a58','5c4f9f9f6c468dad02f46642103f33777ead414c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i26e2.194b27b62a010b30"

  strings:
    $hex_string = { 69 00 6e 00 64 00 6f 00 77 00 73 00 00 00 16 00 82 00 31 00 00 00 00 00 00 00 00 00 10 00 54 65 6d 70 6f 72 61 72 79 20 49 6e 74 65 72 6e 65 74 20 46 69 6c 65 73 00 00 5a 00 07 00 04 00 ef be }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}