rule k2321_22664a504a9348ba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.22664a504a9348ba"
    cluster      = "k2321.22664a504a9348ba"
    cluster_size = "18"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy backdoor"
    md5_hashes   = "['1438fd097ea573fe75b580bd1b8e8085','207031fb059cd7009b6e27d10704bdc9','bf0a44d142706638eab83fea863cc690']"

  strings:
    $hex_string = { 9f 45 8d 09 97 ba f1 62 d5 e9 79 10 75 2c 44 85 c7 a2 05 92 cc 91 c4 41 8a 81 fc 7e 00 5c 15 d0 ec 37 33 cb 0b 70 fa 94 30 d1 11 50 df 84 64 ab d2 83 4f 4d 06 f8 66 82 ca a6 76 80 7d 99 54 13 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}