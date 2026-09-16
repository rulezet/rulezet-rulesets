rule i2321_0253b6c9cc000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.0253b6c9cc000b16"
    cluster      = "i2321.0253b6c9cc000b16"
    cluster_size = "13"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmicduke backdoor razy"
    md5_hashes   = "['0855c0cf58d017f86bd60ae40c924d47','2536c22e1a2bdff90d146bd7eb7bb345','f560be87abed8607147038423b4efc52']"

  strings:
    $hex_string = { 6a a9 10 4e 8e 8c 3f 3d 32 7a f0 89 ac e3 70 b0 fd ab 0b 17 6b 73 d5 fa b9 42 98 9c 18 19 df 8c 57 77 8c 97 5e 18 5b 2c d5 2e 4f 15 2b 8b a5 91 4b b1 e7 62 1a 7b 26 ce ee 64 e9 72 1a 38 3a 3c }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}