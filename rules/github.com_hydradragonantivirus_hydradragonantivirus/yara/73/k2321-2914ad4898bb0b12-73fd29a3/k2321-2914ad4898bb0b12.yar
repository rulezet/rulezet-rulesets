rule k2321_2914ad4898bb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2914ad4898bb0b12"
    cluster      = "k2321.2914ad4898bb0b12"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy emotet tinba"
    md5_hashes   = "['05c11499801599b039dffc88b75b8b0b','22269eb5201f9ae41bff2ecb318bdb7a','fc7e2f6d5331ebe44faf2c088f9a2f8a']"

  strings:
    $hex_string = { 52 38 6f 10 3d 39 3b 06 b2 77 0c e0 ec e8 cf de 35 80 f5 46 3f e6 96 3e ec f9 89 bc a9 d1 e2 d4 48 6d 7c 78 90 d1 a0 57 c8 65 22 1e 97 c7 61 b6 5f af f3 b8 70 2c 9d 56 1b 6a 08 88 37 aa 93 0d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}