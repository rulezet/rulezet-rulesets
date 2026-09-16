rule k2321_13959a50dcc27916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.13959a50dcc27916"
    cluster      = "k2321.13959a50dcc27916"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "regrun ludbaruma rontokbro"
    md5_hashes   = "['4207b0b6409b2aa909badb463b75424a','47f17c4092dce6d6ffc4e0097449ae50','dae74da8bbf4ae49abaa68a80872bc67']"

  strings:
    $hex_string = { 8d ee 51 a3 3b f4 2d 11 35 3a d5 ed 15 da 7a 78 a6 f9 f8 0e 6d 69 cf 32 8c ea a7 57 67 13 1b e0 c5 99 25 04 12 d0 86 65 63 56 5e a8 b0 2a 3d 29 2b 7b e1 bd 99 f5 94 f6 ce 6c 62 0d bc 31 b3 44 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}