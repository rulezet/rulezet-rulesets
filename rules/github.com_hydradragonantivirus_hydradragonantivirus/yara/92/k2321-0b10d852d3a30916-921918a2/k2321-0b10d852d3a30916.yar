rule k2321_0b10d852d3a30916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0b10d852d3a30916"
    cluster      = "k2321.0b10d852d3a30916"
    cluster_size = "50"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hupigon backdoor razy"
    md5_hashes   = "['0518df9c532c05cdeefae2fd1e08e6f3','07464e2e4120cef3be4ed1fa81d78553','5644b4721628983fc29afaedcc202dd4']"

  strings:
    $hex_string = { 0d 7f e8 6b ac 6f 96 7a a7 10 2f 6a d5 79 3b 25 d4 b1 e5 a1 78 9f e0 eb 46 ff b3 9e 65 7d 07 68 88 dc 09 17 0a 8b 26 fd eb b9 94 58 fa 3e 9a db 69 87 a8 5d 3d fc 76 8d 9c bb 40 f7 ba bd 97 34 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}