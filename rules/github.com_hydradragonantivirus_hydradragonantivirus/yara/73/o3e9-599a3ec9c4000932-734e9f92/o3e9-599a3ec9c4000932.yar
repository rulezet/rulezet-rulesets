rule o3e9_599a3ec9c4000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.599a3ec9c4000932"
    cluster      = "o3e9.599a3ec9c4000932"
    cluster_size = "121"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock tdss nabucur"
    md5_hashes   = "['0016c16cf4a1c8178d88202a214e0611','03e56022913bdba48101afdd2d453995','4c7a5f45120ccda4f4bfca78767885d7']"

  strings:
    $hex_string = { 00 9b 36 09 00 82 49 14 00 26 59 20 00 39 33 0d 00 43 2b 07 00 51 54 4b 00 3e 6f 6c 00 0c 1a 0e 00 0a 09 06 00 23 1b 0a 00 3b 35 0b 00 4a 23 02 00 4f 24 02 00 60 40 15 00 7d 71 49 00 9c 3d 0d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}