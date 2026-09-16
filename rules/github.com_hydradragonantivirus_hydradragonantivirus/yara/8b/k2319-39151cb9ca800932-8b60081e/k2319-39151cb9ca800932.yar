rule k2319_39151cb9ca800932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.39151cb9ca800932"
    cluster         = "k2319.39151cb9ca800932"
    cluster_size    = "16"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['7fd92fb94e6f765ccafebf3e3517942007fcde2e','4eb2f601200429c581977530ce1c50773cc73b6d','2b0711858dfb4f1e0d7734fadc75d0ee70e5ee41']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.39151cb9ca800932"

  strings:
    $hex_string = "k};for(var m0J in Y6W0J){if(m0J.length===((0x1FC,1.489E3)<0x1E8?"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}