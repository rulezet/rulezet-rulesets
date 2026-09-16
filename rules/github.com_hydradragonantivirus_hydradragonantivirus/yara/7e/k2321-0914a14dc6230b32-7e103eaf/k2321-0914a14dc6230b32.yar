rule k2321_0914a14dc6230b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0914a14dc6230b32"
    cluster      = "k2321.0914a14dc6230b32"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['34083820fbf48e541677fe049e06a0b2','42203bf0bee30d0ccb85d343d3e78c55','f053a172f849df1704b7efa39064bb21']"

  strings:
    $hex_string = { 96 7a 4a 14 f5 3e e2 15 bb 64 e0 56 a9 4e 8a 86 65 ef 87 1a 4d b2 3a 69 cd 60 a6 57 f4 95 49 9a e4 90 94 f8 21 33 91 55 fa b3 63 55 31 74 7d c3 67 cb 43 dd 84 82 98 c4 44 04 f1 e7 24 c2 cc d1 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}