rule k26bb_6a92d79d9a6b0912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.6a92d79d9a6b0912"
    cluster         = "k26bb.6a92d79d9a6b0912"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dotdo filerepmetagen malicious"
    md5_hashes      = "['4b2c68ef961fdb0a6e726201a16ef0865a0f8404','c0ccc0b0b42a3a0137749c64868cdac580385e1c','37d0b458f56442bfc2f58597d6332d4f531ec7b4']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.6a92d79d9a6b0912"

  strings:
    $hex_string = { d0 80 e2 01 f6 da 1b d2 81 e2 20 83 b8 ed d1 e8 33 c2 4e 75 ea 89 04 8d 70 c5 42 00 41 81 f9 00 01 00 00 7c d5 8b 54 24 10 8b 44 24 08 85 d2 f7 d0 76 23 8b 4c 24 0c 57 0f b6 39 8b f0 81 e6 ff }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}