rule k3e7_3a6365668dfb5132 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e7.3a6365668dfb5132"
    cluster      = "k3e7.3a6365668dfb5132"
    cluster_size = "17"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "smforw smsspy androidos"
    md5_hashes   = "['0b482f50e2dd774b791f4b602970ff97','0f1f2a430e713fc7e9e0762ca47bb698','df6344cd229fdc2a844c33217dab2766']"

  strings:
    $hex_string = { 07 0e 3c 2d 00 17 02 f9 05 cc 04 07 2c 02 24 3b 02 5f 1d 8a 8a 87 03 04 b3 05 29 69 03 00 8a 03 a2 01 01 12 0f 2d 01 14 11 79 85 2f 03 05 86 06 3d c3 03 01 99 03 54 96 03 03 ec 04 67 4b b5 5e }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}