rule k2321_29251162d9eb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.29251162d9eb1932"
    cluster      = "k2321.29251162d9eb1932"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus barys vbkrypt"
    md5_hashes   = "['24e7a21639ec6afd9b1d86999c2b2a71','7e059dae7ef7861e274a524042a82d93','f9dcead2b5d1aafefed89970db853169']"

  strings:
    $hex_string = { dc 40 4a 97 9f 8c a1 80 5f 44 08 f8 45 c7 5d d6 c6 71 26 52 35 ee b4 e5 1a 6c cb 9b b1 2d 7f 18 79 d5 77 23 a3 e4 b8 4b 60 27 39 8a 25 05 dc d3 5a 0b 74 aa c1 5e 6d 03 be bb 19 c5 5e 55 fc ec }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}