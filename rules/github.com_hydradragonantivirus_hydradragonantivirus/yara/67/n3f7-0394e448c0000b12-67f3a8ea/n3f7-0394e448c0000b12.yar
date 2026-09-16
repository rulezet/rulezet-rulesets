rule n3f7_0394e448c0000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.0394e448c0000b12"
    cluster      = "n3f7.0394e448c0000b12"
    cluster_size = "13"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "faceliker script clicker"
    md5_hashes   = "['1e1abdee5b30af96cade2918d3785971','3450e497179f2845d5b6d2c8c06e421d','f8b64d69fb999004f88b4ae69fb2d495']"

  strings:
    $hex_string = "ElementById('HTML1'), {}, 'displayModeFull'));\n_WidgetManager._R"

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}