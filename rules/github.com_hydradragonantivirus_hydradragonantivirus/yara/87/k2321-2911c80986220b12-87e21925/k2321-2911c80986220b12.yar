rule k2321_2911c80986220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2911c80986220b12"
    cluster      = "k2321.2911c80986220b12"
    cluster_size = "17"
    filetype     = "gzip compressed data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "brontok email pazetus"
    md5_hashes   = "['09e4ff0a8163c5058ca3891eca8bb62f','21a329620a2eace1281cb9d02715a4a4','dc46af522f3afff4795399ccdcc6d796']"

  strings:
    $hex_string = { b4 be b9 bc 02 e6 e8 d2 34 d5 0b 5c de eb 1c 8d 5b df f4 ab 3e fb 48 83 b2 00 51 24 09 a2 70 b1 75 e6 59 62 a1 16 6b 9f ed 53 4d 3c c0 6a f5 6d 43 e0 85 45 7b 29 e2 99 64 e9 a8 5e f1 d7 fa 4e }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}