rule o26ef_291e3ca9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26ef.291e3ca9c8800b12"
    cluster         = "o26ef.291e3ca9c8800b12"
    cluster_size    = "3097"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "coinminer miner malicious"
    md5_hashes      = "['2f7595bef59e176de7aabca28ec1caa75f46edb1','5a693f410c1cbd81c4bb70b20ba42b338034ddc1','bdd3dcf9babfe8ad107ea1aa911ce4b53ee0e9a9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26ef.291e3ca9c8800b12"

  strings:
    $hex_string = { 43 38 48 85 c0 75 1b ff 15 69 b3 12 00 8b c8 0f 28 74 24 50 48 83 c4 68 41 5e 5f 5e 5b e9 f4 ef 01 00 f2 0f 10 05 84 f3 17 00 66 0f 2e c6 48 89 6c 24 60 4c 89 73 40 7a 07 75 05 49 8b c6 eb 63 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}