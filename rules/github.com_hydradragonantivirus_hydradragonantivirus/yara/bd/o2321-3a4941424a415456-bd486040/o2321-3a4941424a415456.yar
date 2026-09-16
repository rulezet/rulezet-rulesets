rule o2321_3a4941424a415456 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o2321.3a4941424a415456"
    cluster      = "o2321.3a4941424a415456"
    cluster_size = "9"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['16efa98bd34effaa731abad5be632219','1b63e0a84f71f96f2b2625775ad3ec38','fc51927224713ea2dfe843cd7b67498d']"

  strings:
    $hex_string = { 72 71 62 ed ab 46 cd 04 eb 6e a8 50 8e 58 4a 29 67 b5 36 91 7d 16 6a a4 e1 89 a9 56 15 11 7e 92 05 a5 23 09 20 e3 85 c9 fa 3c 52 aa 01 2e 34 73 3e 4c cc fd 9a 9f 35 d1 1b 24 07 b8 2d d7 90 d8 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}