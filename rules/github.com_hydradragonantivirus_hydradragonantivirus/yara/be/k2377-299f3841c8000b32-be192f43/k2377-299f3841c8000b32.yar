rule k2377_299f3841c8000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2377.299f3841c8000b32"
    cluster      = "k2377.299f3841c8000b32"
    cluster_size = "4"
    filetype     = "HTML document"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "redirector html script"
    md5_hashes   = "['3fbf9fef3bb74f33137be9bb3b1eb52a','6c463859434e6570d2eaa7a63378d0a5','9b88c60adece65a64bf63443d9971b75']"

  strings:
    $hex_string = "'1996-2000 Inter-Computer Technology Ltd.'>\r\n<META NAME='descrip"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}