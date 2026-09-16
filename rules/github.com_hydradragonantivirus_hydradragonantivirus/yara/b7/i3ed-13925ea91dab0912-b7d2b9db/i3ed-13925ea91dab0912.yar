rule i3ed_13925ea91dab0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ed.13925ea91dab0912"
    cluster      = "i3ed.13925ea91dab0912"
    cluster_size = "160"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor padodor symmi"
    md5_hashes   = "['00812ae3471c6394639fb5e518a69b7d','01a5acc5b39dd4213d99f1a47b9d973b','444cddc565fa9dad972fc0ac3aa79b88']"

  strings:
    $hex_string = { 7b 08 8d 0c 76 8b 34 8f e9 62 ff ff ff 31 c0 eb 19 55 8d 6b 10 6a ff 53 e8 a5 fe ff ff 83 c4 0c 6a 0b e8 3f 04 00 00 83 c4 04 5d 5f 5e 5b 89 ec 5d c3 55 89 e5 53 56 57 83 7d 0c 01 75 05 e8 23 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}