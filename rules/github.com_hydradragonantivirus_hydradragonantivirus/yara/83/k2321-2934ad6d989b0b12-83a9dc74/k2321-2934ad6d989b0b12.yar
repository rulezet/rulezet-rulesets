rule k2321_2934ad6d989b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2934ad6d989b0b12"
    cluster      = "k2321.2934ad6d989b0b12"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy vbkrypt"
    md5_hashes   = "['938200a266b8491e05b010a2388bc8c9','cbbc351e6349faecfb4676df40e42716','fc5e14d38bd6767cab12bd3a72b01bf1']"

  strings:
    $hex_string = { 4d c8 b4 3b 44 df ec 09 f6 02 eb 84 85 e8 5b 32 55 fa 65 92 f6 05 72 b3 89 36 8b 0e 60 5d f8 68 81 01 88 69 ae 1a a3 6f b6 7f 62 db 6c d5 7c ab 40 1f 9c 4e 76 ce cd 24 ec 97 9b 41 74 b5 e4 ca }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}