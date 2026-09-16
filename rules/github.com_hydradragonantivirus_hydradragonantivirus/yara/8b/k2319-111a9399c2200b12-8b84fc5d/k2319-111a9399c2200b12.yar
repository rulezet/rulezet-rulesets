rule k2319_111a9399c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.111a9399c2200b12"
    cluster         = "k2319.111a9399c2200b12"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['bcb10c36ec43ee25aae463cdc9d7bbe805008666','41d4e96ef55ee45adbc72956cade0490a5935217','963adfe37e244deff3e7eaac361bc11ccb43425a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.111a9399c2200b12"

  strings:
    $hex_string = "(37.,8.0E2)))break};var V1l3F={'p9O':\"g\",'n3F':function(D,y){ret"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}