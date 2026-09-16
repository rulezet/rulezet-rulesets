rule o3e9_139128a1c2000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.139128a1c2000b32"
    cluster      = "o3e9.139128a1c2000b32"
    cluster_size = "413"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "itorrent loadmoney malicious"
    md5_hashes   = "['002edbdb0319fbea69636ede7a567392','00710a6e51980031101f1756d691cd2e','0910e1feb28a5a3b56aee9b3d3ab645c']"

  strings:
    $hex_string = { 8c bf a9 47 6f 66 a1 da d0 b0 a2 1c 2c 86 94 26 5b c9 24 02 78 68 16 5d b1 99 df c5 79 bd aa e0 e7 21 71 62 59 0c 22 75 ee de 3e 7f 41 b6 f9 d9 14 89 81 c2 1a f2 3c 27 c4 c0 a4 9c 25 53 17 63 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}