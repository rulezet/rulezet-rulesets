rule k2321_0b30d349dfa30932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0b30d349dfa30932"
    cluster      = "k2321.0b30d349dfa30932"
    cluster_size = "10"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jtlp kryptik hupigon"
    md5_hashes   = "['08e094a93938fcd04754c8cedd39987d','3721dcb1777516a9fe62207309c9205a','e6ed3aa2cd66e82aa03c3a023ee895e6']"

  strings:
    $hex_string = { d4 12 4b 3a c3 92 78 71 e5 4e 7b 6d cb a2 77 cd e6 4f d7 4a c9 e9 4e 01 9a 9c 03 97 b0 14 0b 09 23 51 56 1f 73 f3 55 3d 63 51 87 c5 8e 8c 2a 0d ca da a6 85 57 18 f1 af 9b b8 f4 5e fa e3 6f 43 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}