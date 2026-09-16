rule k2321_211aa4d596c31932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.211aa4d596c31932"
    cluster      = "k2321.211aa4d596c31932"
    cluster_size = "60"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "brontok eyvjjib fmmfr"
    md5_hashes   = "['01cad3b2daeca21b43402121f0f7e728','044016a65af85752e573e7d6aa9913bf','4665a27035819c3b2aa8fb7f3f5151ee']"

  strings:
    $hex_string = { 76 59 34 56 2d fb c8 6b 44 75 7d b1 b3 ee d7 0b f2 a5 3b 7a bd f6 d4 3a 6d 4b 14 e5 53 ca 0f 7f 27 69 88 4b e8 86 55 cf 1b 45 eb 2b 49 f5 b2 f0 83 16 22 54 52 af a6 dc 98 e2 3f 21 95 04 e7 02 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}