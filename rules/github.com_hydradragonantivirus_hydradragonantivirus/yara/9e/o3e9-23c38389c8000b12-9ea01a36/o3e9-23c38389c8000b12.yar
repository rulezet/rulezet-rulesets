rule o3e9_23c38389c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.23c38389c8000b12"
    cluster      = "o3e9.23c38389c8000b12"
    cluster_size = "45"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "downloadsponsor unwanted riskware"
    md5_hashes   = "['081b1407ed00f0049e43863e96980c34','1aa024df62820dccc25afd4e0ad8e206','91c5e8c946726c217fdf312c7513e68d']"

  strings:
    $hex_string = { c0 c6 ea c5 00 48 72 16 8a 2d 83 b3 8c 25 53 5a e6 b0 98 4f ae 4c 2e 92 5e b1 2c a1 49 62 09 1a ca 9c 3b 6d 74 77 51 bd 90 5c 78 a1 6a 99 eb 30 37 91 20 a6 31 2f 7b 13 e8 45 0e 9a f8 f7 c9 24 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}