rule k3e9_42963841c8001112 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.42963841c8001112"
    cluster      = "k3e9.42963841c8001112"
    cluster_size = "1167"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zbot generickd trojandownloader"
    md5_hashes   = "['007be44c602760da02d296048fab242d','00f3c72e0a03cbdf392a5cb8c45afc13','07a734d0826719ee7d7fcb75eda60076']"

  strings:
    $hex_string = { 74 49 6e 66 6f 3e 0d 0a 3c 2f 61 73 73 65 6d 62 6c 79 3e 00 9a 06 80 01 4d ec 5b 7e 06 80 01 95 6b 77 56 08 80 01 0d e6 a7 cd 0b 80 01 39 fa ca 6d 06 80 01 89 99 d5 67 0c 80 01 c8 c5 be a6 05 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}