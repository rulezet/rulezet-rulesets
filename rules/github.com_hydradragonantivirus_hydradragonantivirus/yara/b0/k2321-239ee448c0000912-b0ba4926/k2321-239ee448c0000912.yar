rule k2321_239ee448c0000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.239ee448c0000912"
    cluster      = "k2321.239ee448c0000912"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['2e947af127fc7fe3ceae1a208cbd37d6','6190128bbb79a41cbc7b40967b2908e7','cf5abb63d88649d5d9273c89cfb92d5e']"

  strings:
    $hex_string = { 3d ff e4 88 c2 42 37 31 41 d0 3a da c6 b7 91 94 0a 7b 3f 90 fb 2c a2 e6 c4 68 63 62 54 2b 47 69 7f 4f c7 85 9b 6c 1e cb c3 b6 56 bd 30 7c 07 87 c9 46 2f f9 40 e9 65 e9 76 4e 8c 05 f0 e5 64 0b }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}