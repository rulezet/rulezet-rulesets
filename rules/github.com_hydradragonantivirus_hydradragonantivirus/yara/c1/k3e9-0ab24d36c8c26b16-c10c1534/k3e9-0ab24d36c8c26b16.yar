rule k3e9_0ab24d36c8c26b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0ab24d36c8c26b16"
    cluster      = "k3e9.0ab24d36c8c26b16"
    cluster_size = "357"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zbot ramnit krap"
    md5_hashes   = "['004b0a08a2f14eb007e53249b223c57e','0059fcd77c4820a4957099ea5744a642','0e56f8a23222c470d025f7fde5341893']"

  strings:
    $hex_string = { ca 74 2a 44 ad a0 04 01 87 46 95 82 0f b0 51 65 4c 12 99 e8 19 aa 10 00 d2 de fa 7f 6b 0e 9b d9 26 03 3c 13 5d 0d f4 76 7a 9a 75 c2 40 e0 7c 17 4b b4 9d d9 8f 1e e4 cf 89 c7 8b da 2f f5 5b 32 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}