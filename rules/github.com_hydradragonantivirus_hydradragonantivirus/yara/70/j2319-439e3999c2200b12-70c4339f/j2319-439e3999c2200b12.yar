rule j2319_439e3999c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j2319.439e3999c2200b12"
    cluster         = "j2319.439e3999c2200b12"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "nemucod script dloade"
    md5_hashes      = "['1d9075f84d39f934b49d7f59647a02c9ae2ef6d4','8ddfda941f82d00c1d720ab3f301c0339ee36f14','56ad8c8b6dbd2cbe14da47ca0652e055c5255a77']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j2319.439e3999c2200b12"

  strings:
    $hex_string = "5+APvOe5DS2rOd/Lrs9XpfZ8kFE7wNlp2NIgcoA0KjjT\nqunsjD3QsRobipmVgC4"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}