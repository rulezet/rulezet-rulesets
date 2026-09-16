rule j3f8_5846b6b018bb0130 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j3f8.5846b6b018bb0130"
    cluster         = "j3f8.5846b6b018bb0130"
    cluster_size    = "24"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "shedun androidos origin"
    md5_hashes      = "['7f839ef89251e2d88cd3f9ff1732a69fb46448fb','04918f34648973698434895a1a7e0eda21b29726','886791c69051ee6abf2010a58dda619579a645aa']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j3f8.5846b6b018bb0130"

  strings:
    $hex_string = { 61 6c 76 69 6b 2f 73 79 73 74 65 6d 2f 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 3b 00 1e 4c 6a 61 76 61 2f 69 6f 2f 42 75 66 66 65 72 65 64 4f 75 74 70 75 74 53 74 72 65 61 6d 3b 00 0e 4c 6a }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}