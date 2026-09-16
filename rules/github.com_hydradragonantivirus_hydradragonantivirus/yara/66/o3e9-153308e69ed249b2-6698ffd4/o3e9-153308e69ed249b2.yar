rule o3e9_153308e69ed249b2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.153308e69ed249b2"
    cluster      = "o3e9.153308e69ed249b2"
    cluster_size = "610"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster bundler installmonstr"
    md5_hashes   = "['00cd992eedf039fcaa3030542783a422','016ef76238cc9b82b864b30e06353641','08390442950bd4e5572c688cc068d567']"

  strings:
    $hex_string = { 6c 01 e2 1d 71 89 39 44 73 83 8f 21 eb 94 e6 d7 bf dd 14 d4 7a e0 33 c8 56 8b 18 07 93 1c ab e8 59 3b ca fb d0 f3 c5 fd f5 35 0e 5e b5 aa db be cc 74 f1 d1 05 ff 28 96 cb 1f d2 12 85 6a 76 54 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}