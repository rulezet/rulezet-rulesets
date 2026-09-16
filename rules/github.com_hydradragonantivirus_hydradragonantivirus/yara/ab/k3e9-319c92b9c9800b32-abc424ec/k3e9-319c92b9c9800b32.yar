rule k3e9_319c92b9c9800b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.319c92b9c9800b32"
    cluster      = "k3e9.319c92b9c9800b32"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jqap small trojandownloader"
    md5_hashes   = "['30710673de3fc5df6bd97a5719fe83c9','86b22a6a93f6454f26df049f07920996','e96ccc41bf90f1c8262e1d8dfb9cf9b2']"

  strings:
    $hex_string = { c7 f5 a7 2f c3 70 b0 ba 32 59 eb 36 49 4b 71 e9 b2 64 fc c4 83 0e 0c 0b cb 95 68 91 94 d2 b1 2b d8 4a 5f cc 08 82 ef cf e7 67 0f 0e 7a 62 b4 99 97 38 f9 39 db da 15 68 c1 1b 28 93 9e 54 de 63 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}