rule k3e9_09b23452d97b4912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.09b23452d97b4912"
    cluster      = "k3e9.09b23452d97b4912"
    cluster_size = "6"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nimnul vjadtre small"
    md5_hashes   = "['195309cce76847c6c0b61ffec6eb1a46','1f615fb292e3d54bf53c250e9829f1d1','eaad5744cffebd7e7136d8a2d7116fee']"

  strings:
    $hex_string = { 2d 50 f7 0e b5 f4 61 cf 4d 72 46 a8 3a d3 dd 7a 81 e3 89 83 e0 28 d7 38 a2 53 91 29 5a 70 1d 04 67 e6 54 f5 e4 2c 62 11 41 d0 d0 b6 d4 15 36 c2 d9 ef d8 9e 6a fb 1f c0 5f ed 09 c7 d2 7b 80 fe }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}