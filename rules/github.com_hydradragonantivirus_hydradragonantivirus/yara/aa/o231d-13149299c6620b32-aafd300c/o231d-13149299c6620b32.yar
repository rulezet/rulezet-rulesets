rule o231d_13149299c6620b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o231d.13149299c6620b32"
    cluster         = "o231d.13149299c6620b32"
    cluster_size    = "8"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smspay riskware androidos"
    md5_hashes      = "['b4f41ae8b5d3f71ead38f73283546f91a49be583','c4ff46778e91069814b1c9ece79ead814758511b','545bace97876696483219b97eb7bad80f9986f88']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o231d.13149299c6620b32"

  strings:
    $hex_string = { d0 ff 56 58 97 4c 93 c6 73 43 f1 85 29 1e eb 70 1a e4 57 e5 35 c2 dc ab c0 bd 80 ba 4f 01 db 30 8b 8d 51 65 e9 6f 15 61 be 67 41 9a 1f c5 f6 24 e3 39 53 dd b3 ad 52 d4 75 3f 49 3c 3b 59 aa 74 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}