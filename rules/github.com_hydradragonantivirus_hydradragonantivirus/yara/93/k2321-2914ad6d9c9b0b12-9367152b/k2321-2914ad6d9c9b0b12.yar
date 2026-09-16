rule k2321_2914ad6d9c9b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2914ad6d9c9b0b12"
    cluster      = "k2321.2914ad6d9c9b0b12"
    cluster_size = "9"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba emotet zusy"
    md5_hashes   = "['0edc6b9d3ab242e1ce4e87df1a831d8a','22dee8ee007dd5222cfbcac6388de893','f92160187a7cf2d42645721c74ab78fd']"

  strings:
    $hex_string = { ce ce cf df f9 da 6b c7 8f 1e 75 3a ec 56 ab f5 d8 d1 63 60 de 07 ef bf d7 c6 e7 95 2c 16 97 85 92 5d 48 62 25 c2 12 42 b4 58 a4 94 4a 02 d5 2a 44 91 d0 40 1d f6 c4 88 80 d6 a0 22 bd 06 4b c0 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}