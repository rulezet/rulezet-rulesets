rule p26d7_13334cc344000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26d7.13334cc344000b12"
    cluster         = "p26d7.13334cc344000b12"
    cluster_size    = "151"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious attribute engine"
    md5_hashes      = "['7b9e3c0c7bf057664e9e6588ad6142359d8ce69a','291923d1477c21b001a9e3b45bba022c11172b56','1a8ce7a0abffa846bac5805c4f91c648c800ba88']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26d7.13334cc344000b12"

  strings:
    $hex_string = { 8b e5 5d c2 04 00 00 d8 53 32 b0 20 77 68 4b b1 0a e3 e7 9b 91 ec d3 17 5f 39 d0 aa 52 15 45 93 a5 5b 29 2f 03 aa 7b 05 27 8c e8 5a 7c 66 4e 9b 81 44 7d 05 d5 e6 40 53 56 51 8b f0 51 89 54 24 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}