rule j3e7_7014d6e3c8000310 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e7.7014d6e3c8000310"
    cluster      = "j3e7.7014d6e3c8000310"
    cluster_size = "23"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "shedun androidos risktool"
    md5_hashes   = "['094ffe853963525a84519a8f01e1f24c','2d715eae438cbe48a1c131ff2e0564d4','cd48b9f84f7f2ca5925ae2757c7d7212']"

  strings:
    $hex_string = { 61 6e 67 2f 43 6c 61 73 73 3b 00 13 5b 4c 6a 61 76 61 2f 6c 61 6e 67 2f 4f 62 6a 65 63 74 3b 00 01 61 00 1a 61 6e 64 72 6f 69 64 2e 61 70 70 2e 41 63 74 69 76 69 74 79 54 68 72 65 61 64 00 26 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}