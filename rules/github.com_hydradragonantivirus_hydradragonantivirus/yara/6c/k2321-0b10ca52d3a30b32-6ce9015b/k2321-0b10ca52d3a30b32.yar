rule k2321_0b10ca52d3a30b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0b10ca52d3a30b32"
    cluster      = "k2321.0b10ca52d3a30b32"
    cluster_size = "15"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hupigon backdoor razy"
    md5_hashes   = "['01bf0a4bc3e2f8a2159e76354665c339','3e7e19bd7fa77160f744af56add46e0a','fea7dd43081b5df0c66cc845c2bb9441']"

  strings:
    $hex_string = { 77 71 d9 18 eb 08 c7 ca c3 3c 94 91 3e 84 f2 0f 16 d7 1e 48 ee 61 ad d3 b8 75 e2 44 ec 68 c5 30 4d f6 92 31 9f a8 7a bb 0e ba 17 af 55 03 49 e3 9b ad 7c 02 2d 7d 5b 52 fc 8e dc 53 35 a7 3b 6e }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}