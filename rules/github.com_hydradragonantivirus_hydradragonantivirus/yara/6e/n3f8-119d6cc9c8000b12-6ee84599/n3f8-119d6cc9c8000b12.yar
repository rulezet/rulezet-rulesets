rule n3f8_119d6cc9c8000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.119d6cc9c8000b12"
    cluster         = "n3f8.119d6cc9c8000b12"
    cluster_size    = "44"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bankbot adlibrary androidos"
    md5_hashes      = "['14dd62625f796e7ec855dc7f5e7801f13e6fe1bb','93e63238119cd45e699902815e4e1acd25c4960c','971db75b19fe120ce4493d6d9e5092d0424ed2bf']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.119d6cc9c8000b12"

  strings:
    $hex_string = { 53 79 73 74 65 6d 3b 00 15 4c 6a 61 76 61 2f 6c 61 6e 67 2f 54 68 72 6f 77 61 62 6c 65 3b 00 29 4c 6a 61 76 61 2f 6c 61 6e 67 2f 55 6e 73 75 70 70 6f 72 74 65 64 4f 70 65 72 61 74 69 6f 6e 45 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}