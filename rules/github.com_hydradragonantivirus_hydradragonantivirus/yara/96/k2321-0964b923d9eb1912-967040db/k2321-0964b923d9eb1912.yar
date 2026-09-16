rule k2321_0964b923d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0964b923d9eb1912"
    cluster      = "k2321.0964b923d9eb1912"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus conjar autorun"
    md5_hashes   = "['079a76ff76e12983dac26fc99b46ff5a','3caf24f7965c27e39a31793276f45ca4','78df23271c0b59b8a4fe198533f94468']"

  strings:
    $hex_string = { 70 cc 12 4d fe 0a 16 45 90 f6 cb f2 57 31 2c db 7b cc 39 d4 ed 1e f9 0a 58 5f 67 76 a2 a3 85 26 50 b9 5d be 8b 81 d3 ab 8f d9 83 df 9e fc 01 25 0d 44 40 14 4a 52 ad 21 55 5a 7d a9 93 09 56 88 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}