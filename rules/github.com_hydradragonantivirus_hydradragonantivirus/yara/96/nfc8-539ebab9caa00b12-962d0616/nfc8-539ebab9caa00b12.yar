rule nfc8_539ebab9caa00b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.539ebab9caa00b12"
    cluster         = "nfc8.539ebab9caa00b12"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos andr apbl"
    md5_hashes      = "['dd1ba1b036323454f8e346f274ae1e31b0dab00e','4fd1d318a31917bf7f36dc86a930794a04ca2e48','8f4fb869cd8fb49fa39d85a4025487ab67a214f7']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.539ebab9caa00b12"

  strings:
    $hex_string = { ea c7 f8 77 7d e3 a7 5f a2 f3 eb 83 9c 73 88 2f 94 61 a1 f9 34 e4 7b 3b e5 51 56 47 4f 78 36 9d 71 ff e7 31 df b3 8e 63 da 59 e6 24 49 ab af 43 d2 ea 6b 44 bd 54 07 c6 b7 ec 91 6a 5c 3a c8 99 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}