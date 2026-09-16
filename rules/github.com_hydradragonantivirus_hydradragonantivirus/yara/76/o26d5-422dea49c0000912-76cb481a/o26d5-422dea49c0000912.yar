rule o26d5_422dea49c0000912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d5.422dea49c0000912"
    cluster         = "o26d5.422dea49c0000912"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious gifq"
    md5_hashes      = "['70d9b9bad565c83455a42d1882031a1f081f7c54','beead9cca9d87f59bc24a0cf133a66c66d2efbaf','4d0ca9c01ed8e524a704acb85d5715539fcbb80e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d5.422dea49c0000912"

  strings:
    $hex_string = { 03 29 05 46 1b b2 6c 8a c1 b1 01 94 50 a8 a4 41 10 b9 0d 54 9e 4d f1 83 00 cf 0b d0 45 4e 61 0c 51 ad 49 18 d7 f0 42 67 f4 9a 8e fb 04 71 8d e1 ce 06 32 2f ab 20 e2 ef f2 35 60 dc 98 23 69 2c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}