rule j26bf_091e64c8c0000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26bf.091e64c8c0000b32"
    cluster         = "j26bf.091e64c8c0000b32"
    cluster_size    = "98"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "zusy starter malicious"
    md5_hashes      = "['a28a4a3eeb668e25fae9470cc864ead1a3816b1c','51e8bb2896a93f6aadea467e9ba6126bf1848105','0dd9af151d4862bd4f283029b0bb65cd04edc2d7']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26bf.091e64c8c0000b32"

  strings:
    $hex_string = { 73 4f 62 6a 65 63 74 50 72 6f 76 69 64 65 72 00 41 70 70 6c 69 63 61 74 69 6f 6e 00 57 65 62 53 65 72 76 69 63 65 73 00 45 71 75 61 6c 73 00 6f 00 47 65 74 48 61 73 68 43 6f 64 65 00 54 79 70 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}