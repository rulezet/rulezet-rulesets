rule o3e9_5ad1bec9c4000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.5ad1bec9c4000b12"
    cluster      = "o3e9.5ad1bec9c4000b12"
    cluster_size = "24"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock nabucur ransom"
    md5_hashes   = "['0d071d18931bd01e7ef7d09a2e53a692','7543301f3bbba164a96d41c100b07b73','d5302670440a6ee12a1696a623766dc4']"

  strings:
    $hex_string = { 0c 00 f1 86 0b 00 d6 92 55 00 63 b0 e7 00 40 88 ce 00 13 18 1b 00 17 1e 24 00 4a 74 b7 00 65 93 cf 00 66 a1 e3 00 69 a3 ea 00 59 88 d9 00 2d 6e e4 00 48 78 da 00 6a a2 ec 00 6c a7 ef 00 4f 80 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}