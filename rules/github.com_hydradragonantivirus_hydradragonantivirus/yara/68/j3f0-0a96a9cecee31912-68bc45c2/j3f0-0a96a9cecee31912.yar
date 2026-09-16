rule j3f0_0a96a9cecee31912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f0.0a96a9cecee31912"
    cluster      = "j3f0.0a96a9cecee31912"
    cluster_size = "123"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "graftor malicious malob"
    md5_hashes   = "['03a3423d74a6ea21caa3ae3a1bbff593','04ed7f299302f1fc28e7bb6b08595dfe','18d64188cd7cfe0393ec57ae327b2b71']"

  strings:
    $hex_string = { 70 35 61 95 b6 b5 27 fb 0f 6a 5d 64 0c b6 45 f0 d3 c0 f6 6d 0b 52 02 ee 3c 04 26 41 09 43 0f 80 a2 40 91 6d ec f6 ed 46 06 06 30 a4 12 46 27 74 d5 d8 2d 00 6c ff 76 0a 50 a1 58 44 42 02 65 db }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}