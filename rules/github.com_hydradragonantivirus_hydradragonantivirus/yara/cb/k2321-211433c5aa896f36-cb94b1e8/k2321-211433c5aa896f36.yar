rule k2321_211433c5aa896f36 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.211433c5aa896f36"
    cluster      = "k2321.211433c5aa896f36"
    cluster_size = "15"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['06a8f728f34b357c6dc00b9c5a029902','0aa0c23c3e75b849532a76b7812c196e','e02f6cd8d0d10d3f7575368a4d415c17']"

  strings:
    $hex_string = { 2d 68 23 54 87 44 25 c0 27 06 5a 08 d5 21 c3 1c be 91 7f 5b e9 b6 cf 0f 31 13 13 1f 5f eb b1 c8 16 3a 98 e1 76 cc af 37 d7 17 56 67 8b 89 db 3d e8 77 ef 8f 6f a9 2e b2 85 d7 d2 50 9b fa bc a1 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}