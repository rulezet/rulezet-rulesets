rule k2319_3a189ca9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.3a189ca9c8800b12"
    cluster         = "k2319.3a189ca9c8800b12"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script adinject"
    md5_hashes      = "['15caf9a8e0f04f86862fb075c5539625def113df','a9a79343af0840af2a53e718575b83c318c2fdfd','d6e29ace612994d3fa5be6ce89ffe8fa42c25410']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.3a189ca9c8800b12"

  strings:
    $hex_string = "03.,56.)))break};var u8w1={'N24':function(Y,z){return Y<z;},'F7Q"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}