rule o3f1_491b3949c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f1.491b3949c8000b12"
    cluster      = "o3f1.491b3949c8000b12"
    cluster_size = "7"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dowgin androidos inoco"
    md5_hashes   = "['2dd5885bb7eed3d91d1e56bb360f24f9','340c50f2b2c430e8664e96fb81b1df2a','ebfce2005675287b905c86847be5ef32']"

  strings:
    $hex_string = { 23 8a 42 4b 09 8e 4a 02 8c eb b1 40 f2 30 49 f9 25 51 34 15 9f 32 7a 27 cf 26 b2 13 4d 78 a4 c0 33 22 31 6d a1 3a ca b6 44 e7 ea 6b 72 19 50 54 f1 90 28 99 64 d3 56 6a b5 cc ad c8 1f 9e ac 73 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}