rule o3e9_711dbcc9cc010b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.711dbcc9cc010b16"
    cluster      = "o3e9.711dbcc9cc010b16"
    cluster_size = "367"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "lethic malicious ayzg"
    md5_hashes   = "['009b550c27444337e0842abd5600f82f','012f194b6a390ae40b54e427a1d6ac9e','123a6e53186fe76be6999ceeae574b93']"

  strings:
    $hex_string = { 1a 3d 25 0c 09 00 34 d2 7f 5f 31 58 09 9c f3 eb c9 65 0b c0 3c f8 26 92 5a f1 fe 9e 23 97 84 5d ab 0f 22 e0 f9 88 a0 02 b5 19 b8 f7 66 d8 5e 13 3d c4 7d c3 d8 ba d1 73 b4 73 6e 31 d4 9c 31 7c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}