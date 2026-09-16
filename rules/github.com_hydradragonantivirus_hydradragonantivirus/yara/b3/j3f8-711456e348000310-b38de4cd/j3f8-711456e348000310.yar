rule j3f8_711456e348000310 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f8.711456e348000310"
    cluster      = "j3f8.711456e348000310"
    cluster_size = "9"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "shedun androidos piom"
    md5_hashes   = "['36239c970d0c5be8899ba1a68382fb8b','68b184dae06f6b6ad598b704336bb47d','c3f49d2d81f868a3facfe4a02a2aedea']"

  strings:
    $hex_string = { 67 2f 4f 62 6a 65 63 74 3b 00 01 61 00 1a 61 6e 64 72 6f 69 64 2e 61 70 70 2e 41 63 74 69 76 69 74 79 54 68 72 65 61 64 00 26 61 6e 64 72 6f 69 64 2e 61 70 70 2e 41 63 74 69 76 69 74 79 54 68 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}