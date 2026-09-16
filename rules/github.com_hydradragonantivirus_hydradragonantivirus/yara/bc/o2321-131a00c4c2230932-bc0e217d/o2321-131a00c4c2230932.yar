rule o2321_131a00c4c2230932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o2321.131a00c4c2230932"
    cluster      = "o2321.131a00c4c2230932"
    cluster_size = "1140"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dinwod nimda deepscan"
    md5_hashes   = "['0023b370f3d7de98e79c705e6ad7f55c','0025fbb95cc48480946ae5f36a86909e','03d372a6a9a0a306d264a878c7f112ed']"

  strings:
    $hex_string = { 05 ae 36 1a a5 75 74 84 92 45 7f 87 bc 6a d6 09 6f f0 9d 51 78 df 9c 22 0b 23 a6 f6 d9 62 3a 0f 9e 86 1b 8e d2 91 81 94 04 7e 64 52 12 53 69 02 56 97 fd b6 46 2b 9b 08 32 18 44 63 34 cb f5 20 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}