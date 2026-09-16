rule k2319_105b16b9c8800b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.105b16b9c8800b32"
    cluster         = "k2319.105b16b9c8800b32"
    cluster_size    = "14"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['17ddbf023b2a3b328ed7f56a347c3e6272b222dd','1e572aaf8677cc4aa29d6064fadd723dbf1c1b0d','0555efad59d21ffd101ec63cd2d231d28e47407a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.105b16b9c8800b32"

  strings:
    $hex_string = "134.):(6.03E2,0xF5)))break};for(var z9Q in s1p9Q){if(z9Q.length="

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}