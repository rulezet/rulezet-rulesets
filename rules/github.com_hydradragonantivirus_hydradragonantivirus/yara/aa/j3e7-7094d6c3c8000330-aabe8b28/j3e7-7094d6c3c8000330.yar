rule j3e7_7094d6c3c8000330 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e7.7094d6c3c8000330"
    cluster      = "j3e7.7094d6c3c8000330"
    cluster_size = "539"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos shedun risktool"
    md5_hashes   = "['008f4fe75025324ac32612eb56fec421','01bf12ede2d62ae4afe03177c6398739','094b94ca089a41afe5372b804a18e212']"

  strings:
    $hex_string = { 0d 67 65 74 50 61 72 65 6e 74 46 69 6c 65 00 07 68 61 73 4e 65 78 74 00 04 69 6e 66 6f 00 06 69 6e 76 6f 6b 65 00 08 69 74 65 72 61 74 6f 72 00 10 6d 41 6c 6c 41 70 70 6c 69 63 61 74 69 6f 6e }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}