rule k2319_392d5ce9c8800932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2319.392d5ce9c8800932"
    cluster      = "k2319.392d5ce9c8800932"
    cluster_size = "3"
    filetype     = "text/plain"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "kryptik script diplugem"
    md5_hashes   = "['384d706caf9ffbe035a4f1e4eb7bed60','467c781958702089eaf2daddd605ff0f','fa1848a509c3ea63752ad2dd7c1b45da']"

  strings:
    $hex_string = "Z5L+J3m.z6L+J3m.R5L)]();}catch(O){}},save:function(K){var I=\"eco"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}