rule i445_09914928c0000b22 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i445.09914928c0000b22"
    cluster      = "i445.09914928c0000b22"
    cluster_size = "4"
    filetype     = "MS Windows shortcut"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jenxcus dinihou autorun"
    md5_hashes   = "['33998718c3e4be1a69c78725713cf8d4','adf6d5f5c5293e75b06736b71ec6d1c1','e20bb89d5c3d04f2d0b749f57069d454']"

  strings:
    $hex_string = { 64 00 69 00 63 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 14 03 00 00 07 00 00 a0 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 49 6e 73 74 61 6c 6c 65 72 5c 7b 39 30 31 34 30 30 30 30 2d 30 30 31 31 2d }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}