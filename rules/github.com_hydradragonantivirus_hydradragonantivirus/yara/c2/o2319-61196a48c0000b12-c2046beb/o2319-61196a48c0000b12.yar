rule o2319_61196a48c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.61196a48c0000b12"
    cluster         = "o2319.61196a48c0000b12"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "faceliker likejack classic"
    md5_hashes      = "['55e67505cd90b4e0a82a02520facc144306506b9','b2287da3bd15aeaac2ef29fd6e80de1dc003c1b1','f88d65382164b9f257ea04d882988f05f4612827']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.61196a48c0000b12"

  strings:
    $hex_string = "y(window,[].slice.call(arguments,0))};\n/*!\n * Isotope PACKAGED v"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}