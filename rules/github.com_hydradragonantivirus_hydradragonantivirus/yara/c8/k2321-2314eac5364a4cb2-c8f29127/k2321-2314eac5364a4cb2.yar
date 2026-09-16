rule k2321_2314eac5364a4cb2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2314eac5364a4cb2"
    cluster      = "k2321.2314eac5364a4cb2"
    cluster_size = "7"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba crypt emotet"
    md5_hashes   = "['347a90b1fc90429e5272493f7a8c1e7e','5f5df9700af9496865d2bb88e1b7f40c','f06cc0ddc2846ce82be9d53d7b5cdede']"

  strings:
    $hex_string = { d4 93 04 44 14 9e 27 73 77 de 0e 9a 3f c1 7c e5 29 9b 35 0b 98 8d c7 6c ac ff 48 8b 94 8f 37 68 f7 cc 01 e1 45 3f 49 c6 a5 c3 d3 a2 fe 15 3d 99 dc 7a 61 34 e6 6a a9 ed f4 18 74 f0 ad 2d fd cd }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}