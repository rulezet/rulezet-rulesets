rule n3f8_396432eb324904e5 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.396432eb324904e5"
    cluster         = "n3f8.396432eb324904e5"
    cluster_size    = "18"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos smforw andr"
    md5_hashes      = "['ecbaf867847faa76a071319da9aabfbbe6cc32aa','55afa2b0a537a189f86c2e739946ccd04a6e78f9','1b2b9500947d2154b7cf49dae0a5f6075a591b42']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.396432eb324904e5"

  strings:
    $hex_string = { 6e 10 25 25 05 00 0c 05 71 20 1e 21 54 00 0a 04 07 14 54 44 e7 02 6e 10 70 25 04 00 28 a5 13 04 e8 03 12 15 07 16 52 66 e5 02 12 17 d8 06 06 ff b8 65 b2 54 01 42 1a 04 0e 0c 12 35 71 20 1c 21 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}