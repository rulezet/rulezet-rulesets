rule k2319_290d12b9c8800932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.290d12b9c8800932"
    cluster         = "k2319.290d12b9c8800932"
    cluster_size    = "14"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['0527e67b4d56ff7ee79500753606c537a9b2e9e1','b11d006f47022c929358a81b356a976027596b8c','cbee1de7e8dc3b20eff8d2e0dbdc2069232b806d']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.290d12b9c8800932"

  strings:
    $hex_string = "{var q=(X[(\"charCod\"+\"eAt\")](l)&((52.2E1,0x21F)<0x7B?4.4E2:(79.8"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}