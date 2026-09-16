rule o3e9_29946995ca230b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.29946995ca230b12"
    cluster      = "o3e9.29946995ca230b12"
    cluster_size = "8"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr unwanted"
    md5_hashes   = "['186ca73e0c70159149c7a33bcfb9954a','43d4c4edb0f686d36aa6a6afa3068b29','fe2f525f575d88d51b55c99cd9ddd088']"

  strings:
    $hex_string = { 75 2e 52 b1 3b 82 e8 a9 08 ae ec 80 8a e1 98 96 5f 8b de 39 5c 64 cf ee 6b c9 e9 b5 28 e2 63 c8 74 51 05 73 69 e7 46 d1 81 5e 48 ce 17 61 f6 0e 37 7b 22 6a 18 44 c4 a7 7f 67 d9 4b 33 01 e4 b6 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}