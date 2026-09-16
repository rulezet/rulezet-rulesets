rule k2318_339192b9caa00b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2318.339192b9caa00b12"
    cluster         = "k2318.339192b9caa00b12"
    cluster_size    = "757"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "iframe html redir"
    md5_hashes      = "['da365fb97357d1cdf733edf67a63d4caaecce187','d13d52dbe3d8e1d2ab6a38fa1e341f3c343931b0','4f1a7986d25ac1fed5932effbbb9d684945e1fed']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2318.339192b9caa00b12"

  strings:
    $hex_string = { 74 64 20 77 69 64 74 68 3d 22 31 30 30 25 22 20 68 65 69 67 68 74 3d 22 31 34 22 20 63 6c 61 73 73 3d 22 69 6e 66 6f 42 6f 78 48 65 61 64 69 6e 67 22 3e d0 e0 e7 e4 e5 eb fb 3c 2f 74 64 3e 0a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}