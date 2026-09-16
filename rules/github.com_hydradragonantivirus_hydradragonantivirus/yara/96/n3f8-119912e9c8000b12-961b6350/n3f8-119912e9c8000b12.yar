rule n3f8_119912e9c8000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.119912e9c8000b12"
    cluster         = "n3f8.119912e9c8000b12"
    cluster_size    = "24"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "bankbot adlibrary androidos"
    md5_hashes      = "['5f28e87459b3e56b406c79cd6fddc945dfce9737','c60788687f515d0b4a92d5326524ee49d3e99f76','420efdb21122df86e1a7b3b7e1b8a76d775c797b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.119912e9c8000b12"

  strings:
    $hex_string = { 44 75 66 66 24 4d 6f 64 65 3b 00 17 4c 61 6e 64 72 6f 69 64 2f 67 72 61 70 68 69 63 73 2f 52 65 63 74 3b 00 18 4c 61 6e 64 72 6f 69 64 2f 67 72 61 70 68 69 63 73 2f 52 65 63 74 46 3b 00 19 4c }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}