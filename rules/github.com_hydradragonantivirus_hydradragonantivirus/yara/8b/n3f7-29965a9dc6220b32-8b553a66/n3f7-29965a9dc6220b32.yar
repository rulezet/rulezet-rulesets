rule n3f7_29965a9dc6220b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.29965a9dc6220b32"
    cluster      = "n3f7.29965a9dc6220b32"
    cluster_size = "5"
    filetype     = "ASCII text"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "riskware xafekopy clicker"
    md5_hashes   = "['446f9e76566f9ddd60ee4e0cb952dafc','4ea6685c8d44ac8e44af049de3ff00f6','fed98aec44c55b883475b8c3c236a3ea']"

  strings:
    $hex_string = { ac 80 2b 1d 46 dd bd 76 a5 ee ff a1 58 8e 9b 6a f4 04 19 32 af ad cd 50 85 44 d0 99 d3 0c 69 6b c6 4c 15 48 42 68 92 f9 bb f2 40 e9 82 7b 51 07 b6 94 90 77 7a 60 87 57 16 fc 12 25 13 89 b9 e2 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}