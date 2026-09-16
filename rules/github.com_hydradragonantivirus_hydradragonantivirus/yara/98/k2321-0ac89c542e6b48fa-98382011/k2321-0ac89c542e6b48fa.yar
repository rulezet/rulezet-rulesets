rule k2321_0ac89c542e6b48fa {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0ac89c542e6b48fa"
    cluster      = "k2321.0ac89c542e6b48fa"
    cluster_size = "6"
    filetype     = "gzip compressed data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy backdoor"
    md5_hashes   = "['1e9fda412ead4b353bb46d58bc0cde0c','2120de8f4749e03f2137bec11958c7a9','bfa5bef621dcfef5e36f51b14cb08994']"

  strings:
    $hex_string = { 70 bb 29 79 4b f7 66 7d 0e 3e d5 b0 b8 e7 c3 cf 2d 93 3c d7 e1 d1 9b 11 8c e0 9c e4 83 63 84 a9 37 df 04 2c 97 af 01 3e 95 9a b3 75 6c ee fa e6 5c ef 74 65 d8 c8 15 5b 22 8a 5f f4 c2 34 f6 72 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}