rule k2319_1a1896b9ca800912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a1896b9ca800912"
    cluster         = "k2319.1a1896b9ca800912"
    cluster_size    = "25"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['3826636cc6acf31bf637003e7839478c22fe903e','fff970461fbcbb7a483f1c3107248a5d5aff44b0','248b994a7179dbc173ca47846071362b064390b1']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a1896b9ca800912"

  strings:
    $hex_string = "!==undefined){return J[C];}var S=((89,1.356E3)<0x1D3?7.7E2:(0x1A"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}