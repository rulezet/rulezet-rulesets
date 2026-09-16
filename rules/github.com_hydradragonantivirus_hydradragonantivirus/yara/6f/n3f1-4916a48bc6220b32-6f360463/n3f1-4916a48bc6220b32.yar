rule n3f1_4916a48bc6220b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.4916a48bc6220b32"
    cluster      = "n3f1.4916a48bc6220b32"
    cluster_size = "63"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hiddenads androidos andr"
    md5_hashes   = "['0869b96637a8f76855fc024f643e0a14','0d5f39d7766698b5cc4c32083976201e','412dead10c22f1d9c7a97d9210332ca1']"

  strings:
    $hex_string = { 53 00 03 15 2c 3f 4e 5d 69 73 7b 80 0e 22 35 4c 74 94 ab bf d1 e0 ed f6 fc 05 23 4f aa d3 f7 09 26 6a a7 e1 fd 07 25 71 c5 f9 6e b9 f5 fb 9d db f2 28 6d b5 e7 02 2e 83 c7 f1 2a 8c da f8 2b 89 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}