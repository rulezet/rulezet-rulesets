rule o3f4_5ab95ec3cc010932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f4.5ab95ec3cc010932"
    cluster      = "o3f4.5ab95ec3cc010932"
    cluster_size = "3150"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "msilperseus hacktool idlekms"
    md5_hashes   = "['00036b63c919d27fe38a82ce50d95dae','00222195fbe5c4258ab9043bf0905065','010c75961f1968d4490d6eba5c49f4e6']"

  strings:
    $hex_string = { 0f 14 89 05 b9 41 c1 1d c9 02 c1 41 54 15 e1 03 fc 33 d5 1d a1 05 d5 41 cd 11 89 04 df 41 bb 13 a9 05 1b 03 33 00 31 00 f9 41 e7 1d 51 00 12 42 ed 1d 51 01 1b 03 f3 1d b9 05 2c 42 4c 1e 61 01 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}