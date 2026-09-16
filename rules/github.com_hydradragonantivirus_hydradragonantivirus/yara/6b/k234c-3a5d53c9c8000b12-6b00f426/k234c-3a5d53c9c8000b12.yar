rule k234c_3a5d53c9c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k234c.3a5d53c9c8000b12"
    cluster      = "k234c.3a5d53c9c8000b12"
    cluster_size = "4"
    filetype     = "Algol 68 source"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "script classic expkit"
    md5_hashes   = "['1c23958b4715b262e372f97fd5e85cb0','20eed1a2076d9c7f7ae67e13492d5667','f6bb9010f42d36556c2364321a4fe55a']"

  strings:
    $hex_string = { 65 72 20 62 6c 6f 63 6b 20 77 69 74 68 20 6e 6f 6e 63 65 20 28 4e 49 53 54 20 53 50 38 30 30 2d 33 38 41 20 c2 a7 42 2e 32 29 3a 20 5b 30 2d 31 5d 20 3d 20 6d 69 6c 6c 69 73 65 63 2c 20 0d 0a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}