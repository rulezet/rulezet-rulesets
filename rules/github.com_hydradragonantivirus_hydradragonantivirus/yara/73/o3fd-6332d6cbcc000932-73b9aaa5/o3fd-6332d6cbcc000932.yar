rule o3fd_6332d6cbcc000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3fd.6332d6cbcc000932"
    cluster      = "o3fd.6332d6cbcc000932"
    cluster_size = "197"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "expiro allinone ccchoh"
    md5_hashes   = "['00647039a6cb0fbd55732b7e10b15cc4','01727b9545b94a9f51d1087cf26f4def','429f7791289ec45a847c413edf686456']"

  strings:
    $hex_string = { a7 cf 3f 5f 7b 8b 81 97 9a 2f a0 ed 8a 4f 0d 15 12 9d 5d 50 46 36 32 af ec 61 6b 77 91 c0 50 7e 10 3a 42 e9 50 a6 7b ce 45 39 bb d2 f5 4b 71 a4 22 79 1f d1 05 fa 56 32 5c a3 01 c2 3d bd 55 18 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}