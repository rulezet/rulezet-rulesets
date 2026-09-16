rule o231b_1396e448c0000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o231b.1396e448c0000b12"
    cluster      = "o231b.1396e448c0000b12"
    cluster_size = "15"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "script faceliker trojanclicker"
    md5_hashes   = "['032098078e0b6545492c1421897d2a3c','10cc6bf0747049d718bade89c1b2d385','f7ba3bd6a7560f0e19e53d2de86d7794']"

  strings:
    $hex_string = "1/v-css/368954415-lightbox_bundle.css'}, 'displayModeFull'));\n_W"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}