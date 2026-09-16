rule o3e9_19320112d7a30912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.19320112d7a30912"
    cluster      = "o3e9.19320112d7a30912"
    cluster_size = "27"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy noobyprotect unwanted"
    md5_hashes   = "['00daa0900c9d6f5d36c356f0b80315b8','194105e0f23f0b8d1e7172c40a1ed9bc','9ce3ccb852b3b3460ab5bc31d4e5f286']"

  strings:
    $hex_string = { 3b 9d bf eb f9 85 99 ba 20 1c d3 a4 14 71 49 03 d1 a0 5c b4 de d4 df 0a f2 e9 16 e0 7d 6b e6 f8 8d 68 4d 2e 3d 36 31 26 9e 1a d0 00 b6 4e 78 ff 28 6e e2 05 54 a1 50 ec 3a e7 90 d5 70 3e d6 84 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}