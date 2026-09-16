rule o2321_6910519cea610912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o2321.6910519cea610912"
    cluster      = "o2321.6910519cea610912"
    cluster_size = "23"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "filetour razy classic"
    md5_hashes   = "['1e02a1f1fa39a5045b4816ff20d87fe1','2085e618177e7ecc685890e29f16e05b','d24697fa9849a26b126282be4eec956f']"

  strings:
    $hex_string = { 21 14 ae d4 79 e4 12 42 93 bd ea 3a c0 b0 8a 7c cc e8 a1 03 c1 48 d7 d7 fa d0 54 f7 9e 84 cd 58 96 76 68 f6 8b e3 ab 80 7f a5 ac f4 35 62 45 d6 da 22 52 87 5d 5e 3d 82 28 59 db d3 0a 44 8e 01 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}