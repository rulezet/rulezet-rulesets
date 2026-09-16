rule k2321_19109fa1ca000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.19109fa1ca000912"
    cluster      = "k2321.19109fa1ca000912"
    cluster_size = "7"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nimnul vjadtre small"
    md5_hashes   = "['00da722d3d865b21b33a8c58fa16e12c','1bf79ec48012310ecab9e8e6fd89ac4e','f69be19219d2b1c0cad9140d5dce24f0']"

  strings:
    $hex_string = { 1b 3f 88 f6 63 3e 42 9f a7 b8 28 2e e1 aa 26 16 79 ad 07 40 c6 66 eb a9 58 7f ec 74 09 ee b7 14 ab fd dd 00 3b 8d c4 d4 7e 19 8b 48 50 75 58 70 76 55 67 23 7c d0 02 93 10 bf 35 d3 ed 77 b0 ea }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}