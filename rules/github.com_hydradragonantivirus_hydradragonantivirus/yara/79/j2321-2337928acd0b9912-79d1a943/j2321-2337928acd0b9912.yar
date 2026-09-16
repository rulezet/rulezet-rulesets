rule j2321_2337928acd0b9912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.2337928acd0b9912"
    cluster      = "j2321.2337928acd0b9912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre generickd trojandownloader"
    md5_hashes   = "['026fb1b8e45b2ca14c7b0fb4c4c74d48','6b6b22fe9e2467268cb29fc2c0ef4e32','c35e44d730ae103ac8ebf56d118d6131']"

  strings:
    $hex_string = { ea 50 6a 2e 03 35 af e3 b5 9d 86 6b 04 92 88 08 20 32 31 60 4d 00 91 e1 81 65 21 44 1d c7 60 11 d1 71 42 63 e0 cf 81 f8 ee 4a fc 1f 85 ba 02 1f 47 34 01 7c c6 3d 96 06 68 38 f0 c4 23 b6 a7 12 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}