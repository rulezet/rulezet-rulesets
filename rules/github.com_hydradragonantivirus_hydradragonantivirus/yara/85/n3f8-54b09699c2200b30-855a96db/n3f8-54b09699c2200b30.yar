rule n3f8_54b09699c2200b30 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.54b09699c2200b30"
    cluster         = "n3f8.54b09699c2200b30"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos ginamster clicker"
    md5_hashes      = "['89dd81231edc442504b23aee05bc64cface71f11','25af1a800de0cf6e64158b221a7f76e5bebd9608','3197aaab8dc276b4fd8e7261be48e699e41c9ee8']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.54b09699c2200b30"

  strings:
    $hex_string = { 74 2f 76 34 2f 6d 65 64 69 61 2f 4d 65 64 69 61 42 72 6f 77 73 65 72 43 6f 6d 70 61 74 41 70 69 32 31 24 53 75 62 73 63 72 69 70 74 69 6f 6e 43 61 6c 6c 62 61 63 6b 50 72 6f 78 79 3b 00 32 4c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}