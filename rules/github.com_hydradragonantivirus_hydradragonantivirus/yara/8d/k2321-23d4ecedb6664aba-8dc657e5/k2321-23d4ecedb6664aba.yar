rule k2321_23d4ecedb6664aba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.23d4ecedb6664aba"
    cluster      = "k2321.23d4ecedb6664aba"
    cluster_size = "17"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba crypt emotet"
    md5_hashes   = "['06e83c1472035bc17fbd629b36c743da','070b97b1be9f24def15367543092011a','fc93cfced5b66d019eec477f9f83066d']"

  strings:
    $hex_string = { 76 61 e2 d0 5f 72 b4 ac 29 13 97 47 3a 0e 99 ae e7 bf 50 a8 c5 14 c9 30 93 27 6a c1 f7 79 da 1c ad 58 cd 48 b6 b7 17 32 6b 2f 64 fe 0f 0a 6d e5 67 46 4c 21 ac 05 08 1d a3 86 7c 4b d1 33 4f cb }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}