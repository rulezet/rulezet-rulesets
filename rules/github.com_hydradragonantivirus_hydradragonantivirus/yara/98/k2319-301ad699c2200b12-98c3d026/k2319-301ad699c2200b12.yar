rule k2319_301ad699c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.301ad699c2200b12"
    cluster         = "k2319.301ad699c2200b12"
    cluster_size    = "47"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik diplugem multiplug"
    md5_hashes      = "['8fa5a239c410c0f216c18260352dbe2578b5b29c','9676ee52dbd258bf1da88bd969e905d65a6ae38a','7507074cd7bd694159c0ef3237adcc39f5916aa0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.301ad699c2200b12"

  strings:
    $hex_string = "fined){return G[N];}var P=((127,82.5E1)<=(14.43E2,91.)?(103.,\"h\""

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}