rule k2319_1a5a83b9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a5a83b9c8800b12"
    cluster         = "k2319.1a5a83b9c8800b12"
    cluster_size    = "11"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['af79b5f4c6773ab991621825b1db90817d7060c6','36723f16dac414d016e46df988327fb06e2a1d3d','ae153688486e88a7704dbeadc651eec90eca7373']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a5a83b9c8800b12"

  strings:
    $hex_string = "10.,93.)))break};var w5Z7V={'s2V':function(S,I){return S<I;},'D8"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}