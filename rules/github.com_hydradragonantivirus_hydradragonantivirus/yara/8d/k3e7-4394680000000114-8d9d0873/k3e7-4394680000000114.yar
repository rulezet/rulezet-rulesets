rule k3e7_4394680000000114 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e7.4394680000000114"
    cluster      = "k3e7.4394680000000114"
    cluster_size = "7"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "metasploit androidos hacktool"
    md5_hashes   = "['0676b9fb22659ee6f6fd9f917f54320b','4e71727b7c0b7ec688f0cf9c83623c7b','cfafaaad31d4eb600bd4777fd985f233']"

  strings:
    $hex_string = { 0a 01 81 1c 62 01 00 00 13 02 90 08 13 03 14 00 71 30 1e 00 21 03 0c 01 21 12 35 20 08 00 48 03 01 00 38 03 83 00 69 01 04 00 71 00 51 00 00 00 0b 02 62 00 0b 00 6e 30 6b 00 40 05 0b 00 bb 20 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}