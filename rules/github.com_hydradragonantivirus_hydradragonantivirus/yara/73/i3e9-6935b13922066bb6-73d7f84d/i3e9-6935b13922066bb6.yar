rule i3e9_6935b13922066bb6 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3e9.6935b13922066bb6"
    cluster      = "i3e9.6935b13922066bb6"
    cluster_size = "41"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fileinfector olwrei malicious"
    md5_hashes   = "['009cd00135fa73d22ea7916f02e921e7','0ba8604959f40a4bf76df95a3e77e523','5f6ae9af6bf82351c7098fc8933da2d8']"

  strings:
    $hex_string = { 59 0e 03 02 f3 a4 08 8a 06 88 07 47 46 e2 f8 04 ac aa e2 fc 08 03 02 ff e4 02 54 c3 04 8b c4 ff e0 c7 45 30 2a 2e 65 78 66 c7 45 34 65 00 8d 45 5c 50 8d 5d 30 53 ff 95 b0 01 00 00 40 85 c0 0f }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}