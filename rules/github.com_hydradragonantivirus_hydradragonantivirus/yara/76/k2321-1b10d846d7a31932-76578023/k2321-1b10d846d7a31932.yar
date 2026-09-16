rule k2321_1b10d846d7a31932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.1b10d846d7a31932"
    cluster      = "k2321.1b10d846d7a31932"
    cluster_size = "10"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hupigon backdoor razy"
    md5_hashes   = "['35e5f44b4048bea0f264fcdcf223ab11','6b1bbc59a2357254f987aacfc2bc8028','f0c9502e60a7f1d194b0498978f4b491']"

  strings:
    $hex_string = { 27 dd c5 65 63 ac 23 1c 2b 0f f3 50 46 fa 10 ca 3f 58 5c 7b 20 b9 87 b5 4e e3 d6 89 13 b1 a3 15 c3 34 d9 4b c6 7c a2 ea ed 3a e8 5e bc 56 0d 24 8d 6f b6 f2 09 b4 f4 6d 49 f1 3b 72 4f d5 9c ee }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}