rule j3e7_7094d6c3c8000130 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e7.7094d6c3c8000130"
    cluster      = "j3e7.7094d6c3c8000130"
    cluster_size = "23"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "shedun androidos revo"
    md5_hashes   = "['06b33c682324f9a29a3a199cf7076dff','06f98f50c09998bca5ff4422ef6935bc','af6a2538f8d9ec9e265c8563eac7d579']"

  strings:
    $hex_string = { 08 6d 43 6f 6e 74 65 78 74 00 13 6d 49 6e 69 74 69 61 6c 41 70 70 6c 69 63 61 74 69 6f 6e 00 0e 6d 4c 6f 63 61 6c 50 72 6f 76 69 64 65 72 00 09 6d 50 61 63 6b 61 67 65 73 00 0c 6d 50 72 6f 76 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}