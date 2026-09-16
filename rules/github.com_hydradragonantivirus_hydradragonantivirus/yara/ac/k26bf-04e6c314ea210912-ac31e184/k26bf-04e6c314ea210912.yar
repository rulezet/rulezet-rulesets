rule k26bf_04e6c314ea210912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bf.04e6c314ea210912"
    cluster         = "k26bf.04e6c314ea210912"
    cluster_size    = "17"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "swiftbrowse browsefox yontoo"
    md5_hashes      = "['2204e7cd1e6fecb309e7fb1674787a6ea284488a','0133ede42e9002975e6824b16e0dd9402c74f102','d6a2cbb7d183fdab6d4b8c4487a3f27fbdde2f7a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bf.04e6c314ea210912"

  strings:
    $hex_string = { 2c 28 06 14 fe 01 2e 05 16 25 2d 0e 2a 07 2c 21 16 0c 1b 2c c0 2b 14 07 08 91 06 08 91 16 2d e6 2e 02 16 2a 16 2d d0 08 17 58 0c 08 07 8e 69 32 e6 17 2a 02 38 9e ff ff ff 6f 7d 00 00 0a 38 96 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}