rule k2321_2354ecedb2664aba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2354ecedb2664aba"
    cluster      = "k2321.2354ecedb2664aba"
    cluster_size = "5"
    filetype     = "gzip compressed data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba crypt emotet"
    md5_hashes   = "['4ff8ae327aecea0cb9a89607d072551d','55c4667c25bb0c477b4a72fcf2692405','d7ad75957e4312eb625ab9d40a8b707f']"

  strings:
    $hex_string = { b5 cc d2 4a 43 a3 ed 7c 7a 17 ac 91 58 20 18 b8 83 f7 e2 74 6b 26 b2 c6 11 af 7e be f5 66 f4 6b ff c9 cf e1 49 ad 3b 7f 96 4e bc d0 39 8d 78 a5 73 1a f1 92 2e 6d 69 7b da ae 8e 35 23 c9 b6 0f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}