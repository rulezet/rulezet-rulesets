rule k3e9_293679e351b2f316 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.293679e351b2f316"
    cluster      = "k3e9.293679e351b2f316"
    cluster_size = "9"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installcore unwanted classic"
    md5_hashes   = "['156eb5011f4e53a859b29ceee2e93c9f','2ee650235598fbb5271b671d3a8d7361','bb63a64a78f0dffa06d19cd045f5575e']"

  strings:
    $hex_string = { ba cb 27 61 55 2a e1 2b e4 9e 34 d7 ce 84 c4 9d 59 46 7e 05 d6 62 bb 9c 44 25 fc 91 be 92 fe 26 f2 74 6e 60 1e 2d 9f aa 75 33 18 71 dd e7 04 76 8c 3e 86 5c 7b 07 e2 a4 08 2f c2 c9 1a ac b3 3d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}