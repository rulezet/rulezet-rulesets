rule k3e9_2d1491d9ca210b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2d1491d9ca210b32"
    cluster      = "k3e9.2d1491d9ca210b32"
    cluster_size = "232"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171121"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zbot awkxpwp wemosis"
    md5_hashes   = "['0252b6678479dc23dc12af5ca1531f8e','033568c4fa748a0eb5c4ffdf878a8a96','16ca79aea352a4c6b836b17aa014daa6']"

  strings:
    $hex_string = { c7 f9 44 3e 09 82 56 ed 9c 3e 0d 2c e3 4b 61 84 d8 92 14 fd 35 0c 65 1d 15 7c d5 01 9b 4e 05 81 21 40 10 46 fd 08 96 6a 10 f8 10 58 6f 54 9c de 6e bc 9e 39 11 4c 67 50 66 7c d5 f1 cf 31 c6 3a }

  condition:
    filesize > 16777216 and filesize < 67108864
    and $hex_string
}