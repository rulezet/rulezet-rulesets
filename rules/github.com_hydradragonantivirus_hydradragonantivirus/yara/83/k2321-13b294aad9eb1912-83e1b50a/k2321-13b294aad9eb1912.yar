rule k2321_13b294aad9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.13b294aad9eb1912"
    cluster      = "k2321.13b294aad9eb1912"
    cluster_size = "42"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos smssend trojansms"
    md5_hashes   = "['0985f17ddc5ecc93a368502f156dc785','12c8025fc3a0bd6ca5fb76fe96a499ca','8f22b92d89828926be18567d01319b29']"

  strings:
    $hex_string = { 47 77 5d 60 ad 16 d4 42 f4 ae 72 b5 39 ac 9a 32 30 1b 6e 89 8b 85 06 e7 2c 9e b7 e5 a5 5a 36 87 10 b2 1a e9 df f8 f0 13 b6 5f cd bd b1 ce 8a 04 74 32 29 27 f6 e8 7c 45 12 d5 40 ff 98 d0 b9 e3 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}