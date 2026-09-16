rule k2321_2914ad65989b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2914ad65989b0b12"
    cluster      = "k2321.2914ad65989b0b12"
    cluster_size = "11"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba emotet zusy"
    md5_hashes   = "['21e377aabf1a205e886fc8dda0120068','44b12657b9bc9a59cadea9f94746cf5f','dc4451d22365c351d27376d2910a48fb']"

  strings:
    $hex_string = { f4 cb 24 ed 0b e4 66 13 6d 16 1d c0 ba f0 d1 02 03 10 d3 5c 35 46 df 6c ff c4 b6 d9 aa f9 56 81 3e 38 9d ec 9c 9b 49 d8 2f 37 83 e8 6a c9 95 eb 87 49 72 73 89 d9 e6 d5 cd 55 05 fa 27 36 57 20 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}