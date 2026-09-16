rule o26bb_30b6e2858ee31314 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.30b6e2858ee31314"
    cluster         = "o26bb.30b6e2858ee31314"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bundler malicious heuristic"
    md5_hashes      = "['f272b06860c7be7b737a5b9681d62c53d6a91c73','f00d91a8c7895efe27ff8e655862c962df6c2070','3e8bd259716bf9c2d32e51ef059d3f2e38ecb28e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.30b6e2858ee31314"

  strings:
    $hex_string = { 8d 46 18 57 50 e8 81 c1 ff ff 89 5e 04 83 c4 0c 33 db 89 be 1c 02 00 00 43 39 5d e8 76 4f 80 7d ee 00 8d 45 ee 74 21 8a 48 01 84 c9 74 1a 0f b6 d1 0f b6 08 eb 06 80 4c 0e 19 04 41 3b ca 76 f6 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}