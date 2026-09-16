rule j26df_6845681cee467b10 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26df.6845681cee467b10"
    cluster         = "j26df.6845681cee467b10"
    cluster_size    = "695"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "adload nsis nsismultidropper"
    md5_hashes      = "['6592b126332e229b7c725f5d3a75c3d21c8b31e1','671dab0aeca7f905225c74873fd06afc204ceb91','002be1eec5b3ae2952b2942c81def172096236cc']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26df.6845681cee467b10"

  strings:
    $hex_string = { 2c 26 69 32 2c 26 69 32 29 20 69 20 2e 72 37 00 6b 65 72 6e 65 6c 33 32 3a 3a 47 65 74 4c 6f 63 61 6c 54 69 6d 65 28 69 29 69 28 72 37 29 00 6b 65 72 6e 65 6c 33 32 3a 3a 47 65 74 53 79 73 74 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}