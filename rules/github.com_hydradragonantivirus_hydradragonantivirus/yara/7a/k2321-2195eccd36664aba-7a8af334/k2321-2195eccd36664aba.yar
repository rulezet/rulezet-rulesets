rule k2321_2195eccd36664aba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2195eccd36664aba"
    cluster      = "k2321.2195eccd36664aba"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba crypt emotet"
    md5_hashes   = "['00cde54215f56b3975cb4ab84ec5ddf9','1141c87a2d7e74123bed3b35bff01048','919683257049fb44a1d6a431682cc4f9']"

  strings:
    $hex_string = { b7 9e 2c 44 6a ae de 7d ca c3 b9 3b 99 8a 75 b1 00 4c bb 33 91 2b 8b 0a b5 df 0f 19 d0 29 af 14 a9 a4 be c4 13 c9 ba 7b 28 69 dd c5 e8 8d 22 6e 75 fd 34 16 e9 61 a0 35 78 d2 e3 f7 76 9c d6 30 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}