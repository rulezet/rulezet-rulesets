rule i2321_07291689c8400b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.07291689c8400b32"
    cluster      = "i2321.07291689c8400b32"
    cluster_size = "4"
    filetype     = "gzip compressed data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmicduke backdoor razy"
    md5_hashes   = "['1b64d4d6a5a2b2e98cbfbce84eaaeff2','524ae7471e2ae1bc960e79a1abd4370a','ebbfadfb670e8b289b8a3ec0565dbb10']"

  strings:
    $hex_string = { c6 5a 7b 43 fa 5e fb e9 c0 dd 3d f9 6d cc ef 89 a7 e1 e5 4d b1 c1 b8 e6 6d 31 f6 da a6 d8 c1 18 3b 10 63 97 36 c5 6a 83 ed f7 e8 2b 9b 62 df 8e b1 42 fe c3 df ff 03 a1 58 6e 56 0f 9f 3f 5f a9 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}