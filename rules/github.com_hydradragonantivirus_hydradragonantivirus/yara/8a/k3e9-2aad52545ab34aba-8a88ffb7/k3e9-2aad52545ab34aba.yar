rule k3e9_2aad52545ab34aba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2aad52545ab34aba"
    cluster      = "k3e9.2aad52545ab34aba"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy tinba flmp"
    md5_hashes   = "['04a31bb4ca494619000b77f7bc93319b','081f90b9ed7ac73c506e98152e937fee','7f3dedc586aac9c5bbe18a1c1a904284']"

  strings:
    $hex_string = { 95 ac eb f3 ca 57 bd c6 39 07 f7 ee 38 2d 81 0b a0 d4 1a 7f b1 56 78 58 e3 2f d2 44 09 f5 bb c8 68 ae 98 69 d9 dd 34 6d 30 33 03 f0 8c 42 2b 99 3e e1 9a 9f 5f c9 0f f7 2a 48 53 d0 05 f9 25 7c }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}