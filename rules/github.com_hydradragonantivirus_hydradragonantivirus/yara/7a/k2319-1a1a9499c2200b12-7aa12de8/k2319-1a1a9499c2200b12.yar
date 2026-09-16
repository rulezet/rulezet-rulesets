rule k2319_1a1a9499c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a1a9499c2200b12"
    cluster         = "k2319.1a1a9499c2200b12"
    cluster_size    = "54"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['c47df77bd088fff8ba812f1742a988d0a7ac37fa','b0aa56044b6eef44fe2df6c8ab2a080d19388820','d070de7f870bdd14720cdf010ae3182632b98e8e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a1a9499c2200b12"

  strings:
    $hex_string = "dow;for(var V7B in w5w7B){if(V7B.length===((0xCF,56)<=3.89E2?(0x"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}