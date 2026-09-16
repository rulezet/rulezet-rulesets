rule k3e9_191c9fa9ca000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.191c9fa9ca000b12"
    cluster      = "k3e9.191c9fa9ca000b12"
    cluster_size = "7"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nimnul vjadtre small"
    md5_hashes   = "['32b1ef9077363ffa6c3b0bcc71a732b3','4393aeb2a386d340c39587fc274f2598','c7f77d48ae7f2ff0cdf6d8c4f4ac0303']"

  strings:
    $hex_string = { 45 6e 88 b0 9d fe 53 48 f1 16 b5 c5 ef c4 75 27 3d 43 3f 57 ca 0a 08 5a 86 96 06 4d 44 e6 dc f4 0f 68 11 a5 ca 66 8e 5e ee 9b b6 7c c9 cc 94 5f d2 4d cd c0 d5 d1 79 0d a8 9c 9f df f2 1b 4c d3 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}