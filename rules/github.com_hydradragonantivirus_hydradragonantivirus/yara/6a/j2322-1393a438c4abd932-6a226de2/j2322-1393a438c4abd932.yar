rule j2322_1393a438c4abd932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2322.1393a438c4abd932"
    cluster      = "j2322.1393a438c4abd932"
    cluster_size = "13"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "exploit html iframe"
    md5_hashes   = "['008ca44d524f6fb2fb3edd5921b1aeff','2297c611f3177467f73dfd996408f41a','f2e9b309c4939042c39e543b7429cc4b']"

  strings:
    $hex_string = "x.php?sekcja=strona&id=297\">Na podrzucony temat.</a> (18)</li>\r\n"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}