rule k2321_2311ccb8d9a30912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2311ccb8d9a30912"
    cluster      = "k2321.2311ccb8d9a30912"
    cluster_size = "12"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "symmi swisyn abzf"
    md5_hashes   = "['28ec2a43ec1cb426c8c92c89e1c32c98','4bf48240c41e263cbc6a1d2ac46d244f','fd5da12a5a1453493b9225f4647abcc5']"

  strings:
    $hex_string = { 30 b6 bc 3c 5f c2 27 4f 72 45 01 ff cd 9d 65 15 8c a1 85 e9 42 df 35 cf 31 b3 fe dc f9 51 9e e2 bb 6f 15 76 66 61 eb 93 be 2e d6 24 d5 c5 10 9a b0 f2 ba b8 89 62 ab 68 1c 52 7c 1f e4 f1 1b 20 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}