rule o3e9_2ca964d97208494e {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.2ca964d97208494e"
    cluster      = "o3e9.2ca964d97208494e"
    cluster_size = "98"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious heuristic kryptik"
    md5_hashes   = "['01add0f2a0c0aa98b0fd904c23c9eda1','0810e4257bdd516ba3dbdefedb89a4a7','2ef4f3d90d4dfcf522e2b7be06c5cac6']"

  strings:
    $hex_string = { 6b 41 dc 8e 23 03 8b e8 87 8f af d9 9f f6 1e 35 a7 3e 3c 31 d5 26 62 20 44 84 d4 74 0e 16 50 dd a9 ea 7d 21 2a 15 63 85 83 57 6d 54 f1 b1 db 68 fa 9a cc 5e ed d3 06 0a 0d 7f e6 9b 1b ef 66 42 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}