rule o231b_0394e448c0000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o231b.0394e448c0000b12"
    cluster      = "o231b.0394e448c0000b12"
    cluster_size = "33"
    filetype     = "HTML document"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "script faceliker html"
    md5_hashes   = "['02a7f28ff0d2570af99b203683f106c0','122d9184de6d366d9b4f26645025fbca','94735b85afe0f34dac6e18af2f32259a']"

  strings:
    $hex_string = "ocument.getElementById('HTML10'), {}, 'displayModeFull'));\n_Widg"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}