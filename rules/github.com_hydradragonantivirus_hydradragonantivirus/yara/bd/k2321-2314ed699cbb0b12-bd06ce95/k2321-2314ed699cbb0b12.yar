rule k2321_2314ed699cbb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2314ed699cbb0b12"
    cluster      = "k2321.2314ed699cbb0b12"
    cluster_size = "7"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "emotet tinba vbkrypt"
    md5_hashes   = "['175cba45604dd898fad562cb213ff8b3','24b3b41db2080ad80d8f8cda05c47806','f94f51e1bdaf0e8af45380bc90745beb']"

  strings:
    $hex_string = { 63 24 c7 01 7c 0e e9 fd 46 a8 8a 11 22 60 84 19 a6 1f 35 76 2a f4 1d b9 36 22 e7 b8 80 6f 0f cd 2d ad fb 31 4c 27 b2 e8 4d c9 d6 db c8 9b 8d 30 bd 69 9a d0 6c 75 cf 90 2f 47 e3 6e 0a 81 2c a1 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}