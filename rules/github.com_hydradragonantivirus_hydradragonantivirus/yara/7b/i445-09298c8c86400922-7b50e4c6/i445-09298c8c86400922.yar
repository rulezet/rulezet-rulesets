rule i445_09298c8c86400922 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i445.09298c8c86400922"
    cluster      = "i445.09298c8c86400922"
    cluster_size = "4"
    filetype     = "MS Windows shortcut"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171121"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "darkbot dorkbot winlnk"
    md5_hashes   = "['3742063c352397196440ef5bfcbb05a4','b7ef394c2ff90b79694abc08fcaa6d8a','f05036bf113d84cce9073ca5cec1931b']"

  strings:
    $hex_string = { 2b 89 cb 01 61 48 dd 8b 2b 89 cb 01 00 9e 04 00 03 00 00 00 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 29 01 14 00 1f 50 e0 4f d0 20 ea 3a 69 10 a2 d8 08 00 2b 30 30 9d 19 00 2f 43 3a 5c }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}