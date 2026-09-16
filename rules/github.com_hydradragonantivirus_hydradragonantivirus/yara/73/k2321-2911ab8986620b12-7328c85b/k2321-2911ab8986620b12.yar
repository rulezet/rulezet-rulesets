rule k2321_2911ab8986620b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2911ab8986620b12"
    cluster      = "k2321.2911ab8986620b12"
    cluster_size = "21"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "brontok email pazetus"
    md5_hashes   = "['0c8a03e38a27714989a632caeb048378','177b3c5fc078ad38cb289950cb4c27e1','cb5446a1d5ba0486bfd775888f15fa42']"

  strings:
    $hex_string = { 68 a5 b9 26 f3 e5 c6 f0 44 b7 48 2a e4 51 ce 16 f6 eb 55 b4 ad d7 b0 7a 69 9f 91 15 2b ee 6c 5a e8 da d2 83 88 ac 61 82 97 b2 d5 41 54 66 10 c4 a4 11 17 9e c2 cf 81 a3 49 ba 80 d9 e3 85 8e c0 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}