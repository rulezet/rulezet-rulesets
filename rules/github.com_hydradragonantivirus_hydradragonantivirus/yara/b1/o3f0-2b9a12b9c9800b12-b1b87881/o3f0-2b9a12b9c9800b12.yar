rule o3f0_2b9a12b9c9800b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f0.2b9a12b9c9800b12"
    cluster      = "o3f0.2b9a12b9c9800b12"
    cluster_size = "2219"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "razy gametool symmi"
    md5_hashes   = "['0009b33bea15a715c9f910c5be7f0838','00158b956d75456c684a543c6bcc15c9','0184f765bfa90606b277d4daeee726c8']"

  strings:
    $hex_string = { 60 91 86 12 29 74 26 45 1c bc a4 56 8a 84 0e 79 71 c0 51 e4 3a 21 b4 1f 88 5e 00 9b 0c 2d 92 8e 2f d2 52 a2 4c 62 67 b9 eb 96 fa f3 a1 35 c1 9c c2 20 7f 7a ee 90 39 c8 e1 7b 1d 53 3d 2b 63 17 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}