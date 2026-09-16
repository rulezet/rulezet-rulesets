rule o3f4_5ab85ac3cc010932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f4.5ab85ac3cc010932"
    cluster      = "o3f4.5ab85ac3cc010932"
    cluster_size = "1719"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "idlekms hacktool tool"
    md5_hashes   = "['00548027f8b1470175f942c86648c5c0','00873e9e122ff6617e62bfe8ee4d0c2a','02597cc4eecef6bb486c6e74bef6f196']"

  strings:
    $hex_string = { 05 e3 3e d8 12 39 05 f7 3e 2e 1b 79 02 ff 3e 00 14 99 03 8a 31 41 1b 51 05 13 3f ef 10 49 04 1d 3f 87 12 59 05 8b 02 22 00 21 00 37 3f 52 1b 41 00 50 3f 58 1b 11 01 8b 02 5e 1b 69 05 6a 3f b6 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}