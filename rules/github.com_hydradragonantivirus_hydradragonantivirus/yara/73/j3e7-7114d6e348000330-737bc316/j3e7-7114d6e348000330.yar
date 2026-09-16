rule j3e7_7114d6e348000330 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e7.7114d6e348000330"
    cluster      = "j3e7.7114d6e348000330"
    cluster_size = "489"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "shedun androidos risktool"
    md5_hashes   = "['003c550fb98472a27cf92d8af877f65f','008dbd9cca16ad9a1f87568d960ea114','067e6a9c24f50e4563accf43680a02e6']"

  strings:
    $hex_string = { 6e 67 2f 43 6c 61 73 73 3b 00 13 5b 4c 6a 61 76 61 2f 6c 61 6e 67 2f 4f 62 6a 65 63 74 3b 00 01 61 00 1a 61 6e 64 72 6f 69 64 2e 61 70 70 2e 41 63 74 69 76 69 74 79 54 68 72 65 61 64 00 26 61 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}