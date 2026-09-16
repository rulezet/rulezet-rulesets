rule j3f7_392156b4de830932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f7.392156b4de830932"
    cluster      = "j3f7.392156b4de830932"
    cluster_size = "10"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "iframe html script"
    md5_hashes   = "['003ad556b6699a2ff9636b95605b08a3','3d67dac5afde16c2205573bb14c07f58','dd4d4638ce44776ebf2bb9f0d037d668']"

  strings:
    $hex_string = "rget=\"_blank\"></a>\n</div>\n<!--Coppermine Photo Gallery 1.4.3 (st"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}