rule o2321_5132088cea210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o2321.5132088cea210912"
    cluster      = "o2321.5132088cea210912"
    cluster_size = "85"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr unwanted"
    md5_hashes   = "['01380a0732cfdf1a045b041d93c7f39b','04ba0bc2d999b073aa5af7a1b325213d','474bc7988d47722f7fbcd28edb94abc8']"

  strings:
    $hex_string = { 8d 77 29 80 33 25 6f f4 e8 32 ea ab 17 13 10 c0 4a 20 99 bd 57 78 dc 91 8c d3 ca 4d 95 2d 65 6d 8b 5a 9e bb 1d 38 a8 03 02 27 5e b5 53 3b 46 37 db 39 9a 2c a9 59 f6 67 71 f2 b4 34 3e eb d0 af }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}