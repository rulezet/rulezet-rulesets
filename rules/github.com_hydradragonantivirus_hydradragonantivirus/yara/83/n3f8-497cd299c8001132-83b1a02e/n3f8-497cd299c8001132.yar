rule n3f8_497cd299c8001132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.497cd299c8001132"
    cluster         = "n3f8.497cd299c8001132"
    cluster_size    = "220"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "sandr androidos kasandra"
    md5_hashes      = "['aebae87dca25820c1ac5c3fa83eb7e00d2aceeda','5e75d53a19eb0ebc1c69f1cc82aaeafa76dd6c93','6c21409b1ff6ad91b6ac46daf4fd7f9230d70652']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.497cd299c8001132"

  strings:
    $hex_string = { 04 b1 43 15 04 b4 42 6e 20 83 00 48 00 6e 10 06 03 07 00 0a 04 7b 44 82 44 52 75 53 01 15 06 80 3f c6 65 7f 55 82 26 c8 65 6e 30 85 00 48 05 54 74 32 01 6e 30 59 02 34 02 54 72 32 01 6e 20 5c }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}