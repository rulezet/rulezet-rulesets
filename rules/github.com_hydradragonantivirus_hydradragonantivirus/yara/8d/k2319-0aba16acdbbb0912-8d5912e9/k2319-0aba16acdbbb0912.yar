rule k2319_0aba16acdbbb0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2319.0aba16acdbbb0912"
    cluster      = "k2319.0aba16acdbbb0912"
    cluster_size = "5"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "redirector fakejquery script"
    md5_hashes   = "['7d4a831c21bedbbb40562e5892a47820','8db0a555007f3a303c8f644843a6a99c','bad72bd18d146554468c7216120550ac']"

  strings:
    $hex_string = "s\\/wp-emoji-release.min.js?ver=4.4.12\"}};\n\t\t\t!function(a,b,c){fu"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}