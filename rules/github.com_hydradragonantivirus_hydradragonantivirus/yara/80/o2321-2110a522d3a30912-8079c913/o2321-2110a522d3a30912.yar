rule o2321_2110a522d3a30912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o2321.2110a522d3a30912"
    cluster      = "o2321.2110a522d3a30912"
    cluster_size = "152"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "graftor hacktool noobyprotect"
    md5_hashes   = "['0245a9f521ec7d50c88f01fd73ec1341','07a672791691d41ed12a6e928870fe12','1d0329a6f792faa98ab2763be221b3c3']"

  strings:
    $hex_string = { a9 8d 7c 86 4b 92 a3 bb ad 3f 8a 3e 0f 64 a8 9f ac 18 e4 49 7d af f7 fc 6c dd 42 eb e6 6a 67 98 5e 2b 53 66 9c fb 2a 72 6b bd 20 9b d0 37 9d 94 b2 87 cf 71 7f c7 28 e3 f4 25 a5 f6 1a b3 b4 c1 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}