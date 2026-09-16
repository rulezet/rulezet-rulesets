rule n3f8_43d56a00c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.43d56a00c0000b12"
    cluster         = "n3f8.43d56a00c0000b12"
    cluster_size    = "214"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "zdtad androidos inoco"
    md5_hashes      = "['4ef350fb038d17381b6b81582b8cce69daf6db9b','82af7430f9fde93d88b2ff9c9ad015f20484e79c','40cf0017af9c24bcdda42cf3ad3c51214334b76d']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.43d56a00c0000b12"

  strings:
    $hex_string = { 0a 62 06 2b 00 71 30 a7 00 20 06 0c 06 6e 20 bb 00 63 00 12 00 01 02 01 10 34 b2 03 00 11 06 33 c2 0f 00 82 07 15 08 a0 40 12 09 6e 59 b8 00 53 87 d8 07 01 0a b0 70 d8 02 02 01 28 ef 82 07 15 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}