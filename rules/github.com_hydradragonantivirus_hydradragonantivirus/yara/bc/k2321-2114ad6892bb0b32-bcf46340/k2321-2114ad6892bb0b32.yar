rule k2321_2114ad6892bb0b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2114ad6892bb0b32"
    cluster      = "k2321.2114ad6892bb0b32"
    cluster_size = "12"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy vbkrypt"
    md5_hashes   = "['0e0f90c1bf97ebc8837afd83f343367e','2770fda2278bed4d4f7ecddd866087bc','fac3db18993f29f8f2e94993147c4059']"

  strings:
    $hex_string = { 5d 59 be f4 d3 4f f7 9c 3e fd 73 63 43 c3 f9 0b 17 3e ff ec b3 97 5f 7e 79 e3 86 0d ed 7c 5e c9 62 22 be 20 78 a8 e5 72 7f ad 16 94 33 e8 b4 e4 cc 0c 7a 88 87 ca b1 c1 c1 44 77 da 02 5c 8c d0 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}