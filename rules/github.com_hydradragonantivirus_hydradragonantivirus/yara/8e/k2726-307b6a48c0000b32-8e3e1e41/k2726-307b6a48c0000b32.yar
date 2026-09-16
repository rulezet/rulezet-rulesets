rule k2726_307b6a48c0000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2726.307b6a48c0000b32"
    cluster         = "k2726.307b6a48c0000b32"
    cluster_size    = "118"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "patched malicious susp"
    md5_hashes      = "['2c9681464a708e28b82facf450b422dfdff707bb','2045627849ede3889e9eb98aff41d63994bedb79','cadf96aa0e2bb052a96360b609e69687a037edc2']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2726.307b6a48c0000b32"

  strings:
    $hex_string = { 5e 5d c2 08 00 cc cc cc cc cc 8b ff 55 8b ec 51 51 53 56 8b f0 33 db 56 89 5d fc 89 5d f8 ff 15 3c 10 ba 77 3b c3 74 49 8d 0c 46 8d 41 fe 66 83 38 3e 75 28 66 89 18 48 48 3b c6 0f 84 30 01 00 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}