rule k2321_2114ad699cbb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2114ad699cbb0b12"
    cluster      = "k2321.2114ad699cbb0b12"
    cluster_size = "13"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba emotet vbkrypt"
    md5_hashes   = "['075f414574e78685f71f3f9677676f7f','14ce56b278c3e7b9aa74e4dd2ab42919','fb7e5c656626f8aeb39f812174b9a929']"

  strings:
    $hex_string = { c1 9b 69 82 37 87 f3 df 1c c6 7f 63 08 ef cd 21 dc 5d 43 b8 6f a4 72 76 a5 72 de 48 e1 bc 41 f4 e4 ec 18 c8 de 31 80 b3 a3 3f 7b d7 00 d6 1b fd 98 5b fa b0 e7 27 f2 32 a2 c5 a9 91 da f8 f0 20 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}