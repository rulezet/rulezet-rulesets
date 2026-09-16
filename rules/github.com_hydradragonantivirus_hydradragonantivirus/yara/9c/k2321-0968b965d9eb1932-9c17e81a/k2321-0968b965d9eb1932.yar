rule k2321_0968b965d9eb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0968b965d9eb1932"
    cluster      = "k2321.0968b965d9eb1932"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus conjar autorun"
    md5_hashes   = "['0f45f5ee3f04c607ff2a79a5022e3f6b','75a3f815ed477e99253ecaa1079322d0','c9ccd61a1972af366bdeeb5732f875d4']"

  strings:
    $hex_string = { ad 2d 99 4e 98 1a 92 d1 86 e1 63 a1 41 3c b1 7a 8b b8 26 df cc 1d d6 a9 eb 52 f3 4a 10 1d 96 1f 76 e7 12 39 5d 1c e4 37 a4 ec a6 31 25 9b 46 94 18 b5 06 ce 78 e1 43 b6 5b 59 fc 6b e2 bb d8 6e }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}