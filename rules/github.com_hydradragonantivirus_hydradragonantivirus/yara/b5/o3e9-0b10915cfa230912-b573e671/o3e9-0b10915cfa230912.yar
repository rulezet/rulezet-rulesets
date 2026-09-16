rule o3e9_0b10915cfa230912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.0b10915cfa230912"
    cluster      = "o3e9.0b10915cfa230912"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr unwanted"
    md5_hashes   = "['1d5df1beb0edb412bae6eccd93b702af','2d792b7db5b010aa7b08ce0e0d499ae4','d5430a1927821b2696b33c74ffefb707']"

  strings:
    $hex_string = { 9f 73 35 58 3a b7 88 a5 14 f0 8d 20 5f 9c a6 43 3b e9 57 b5 1c 70 77 8a d6 6d 07 c1 b2 46 53 93 87 0f e7 ad 0b 6e d5 52 38 d2 ab bc 24 de f9 25 2b 4e 72 d7 29 e6 9d e5 7c 32 0c 80 45 5d e0 2f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}