rule k2319_393596b9c8800932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.393596b9c8800932"
    cluster         = "k2319.393596b9c8800932"
    cluster_size    = "111"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['ed1da728bd0af9c4c30a1f1cbe66f2ccc61fc1ac','57eec7a996b9992d04b9f52de00a8c48b647c37e','6cdb8d25726d44ec6cb9596e3df3d4a24547ef04']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.393596b9c8800932"

  strings:
    $hex_string = "S[R]!==undefined){return S[R];}var L=((118,0x7A)>(136.4E1,95.)?("

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}