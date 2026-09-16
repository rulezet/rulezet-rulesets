rule k2321_292924b49abb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.292924b49abb1932"
    cluster      = "k2321.292924b49abb1932"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus symmi wbna"
    md5_hashes   = "['0efababbaa478d651c8dc1db0954988a','14e74e3000cf7800771ad97dee6fac16','e510e676056b4ca1de550640e6fa8d55']"

  strings:
    $hex_string = { f6 eb 2f 39 00 61 3e 7f 21 ca 74 e3 2a 4f 93 2d af 83 e5 e1 43 0b cd 19 44 05 f2 1e 59 0a 42 8a 16 a6 29 9a 22 34 13 67 a8 9c 9b b0 cf 96 fc 7c 02 ee 3e 9f c6 5d d7 15 48 de a4 32 6c 79 c5 9d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}