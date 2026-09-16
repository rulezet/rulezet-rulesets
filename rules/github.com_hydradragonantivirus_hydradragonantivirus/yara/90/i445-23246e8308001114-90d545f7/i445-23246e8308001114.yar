rule i445_23246e8308001114 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i445.23246e8308001114"
    cluster      = "i445.23246e8308001114"
    cluster_size = "4"
    filetype     = "MS Windows shortcut"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171121"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jenxcus autorun script"
    md5_hashes   = "['6df10e24874a098b99e775fbbed2b32d','9263fee3b6ed6a34e115b51050f3eea2','e38ccab8b2d2e49387e5e34b3b9b70a7']"

  strings:
    $hex_string = { 2e 00 65 00 78 00 65 00 14 03 00 00 07 00 00 a0 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 49 6e 73 74 61 6c 6c 65 72 5c 7b 39 30 31 31 30 38 30 34 2d 36 30 30 30 2d 31 31 44 33 2d 38 43 46 45 2d }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}