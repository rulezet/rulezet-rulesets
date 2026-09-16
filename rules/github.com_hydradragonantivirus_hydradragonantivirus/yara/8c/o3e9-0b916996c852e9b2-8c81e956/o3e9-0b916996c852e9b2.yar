rule o3e9_0b916996c852e9b2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.0b916996c852e9b2"
    cluster      = "o3e9.0b916996c852e9b2"
    cluster_size = "8"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonstr malicious heuristic"
    md5_hashes   = "['06ef5ca30bab0b789b3b046ccf000d80','1d9e280eeec8cf9d993d967d4fcdc75c','f14874cf9df181a43aa8af8de333ddb8']"

  strings:
    $hex_string = { ce 9a 83 5e 49 3f d6 da 51 a0 29 12 ab cc dc c4 0a 39 1d fc ae 1b 59 1f 4a 3e 80 c1 15 f2 47 77 bd 25 fa ad e0 c7 f9 87 d5 b6 54 9c cb eb 92 f1 2b 30 71 5c 13 0c 64 6c 1a 6a 3d 46 32 3a 02 85 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}