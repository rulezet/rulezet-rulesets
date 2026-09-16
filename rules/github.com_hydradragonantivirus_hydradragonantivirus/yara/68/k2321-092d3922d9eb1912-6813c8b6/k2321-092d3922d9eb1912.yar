rule k2321_092d3922d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.092d3922d9eb1912"
    cluster      = "k2321.092d3922d9eb1912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus conjar autorun"
    md5_hashes   = "['07059c085bc321d37837943fcd81fc50','d699fec58388dc86523820bafec51bff','dc0865da2723eb1675d50b4b0926b337']"

  strings:
    $hex_string = { f6 3c ec 35 b0 63 dc 02 3b a6 bd d0 80 5a 71 0b 2f 3f 61 20 60 98 4a a0 cd 80 64 89 c2 f7 76 55 4b 14 be ef 1b 9c b4 33 a7 30 5c 70 e3 d8 23 74 fa 58 6d d9 aa 57 8e 00 2b c1 51 f4 e9 75 56 1c }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}