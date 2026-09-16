rule j3e7_7d14d6e348000110 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e7.7d14d6e348000110"
    cluster      = "j3e7.7d14d6e348000110"
    cluster_size = "9"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "shedun androidos piom"
    md5_hashes   = "['080b6a34a6b24bfad600da864dedf04d','583bdc1279c00384f3c2f924ccc1c25d','f9b1ea3949bb9f20a505292d9519eb74']"

  strings:
    $hex_string = { 2f 43 6f 6c 6c 65 63 74 69 6f 6e 3b 00 14 4c 6a 61 76 61 2f 75 74 69 6c 2f 49 74 65 72 61 74 6f 72 3b 00 0f 4c 6a 61 76 61 2f 75 74 69 6c 2f 4d 61 70 3b 00 04 54 59 50 45 00 01 56 00 02 56 4c }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}