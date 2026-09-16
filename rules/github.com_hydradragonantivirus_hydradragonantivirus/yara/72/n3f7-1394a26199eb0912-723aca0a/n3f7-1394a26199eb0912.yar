rule n3f7_1394a26199eb0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.1394a26199eb0912"
    cluster      = "n3f7.1394a26199eb0912"
    cluster_size = "4"
    filetype     = "text/plain"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "script faceliker clicker"
    md5_hashes   = "['2e8b54399d801999464a233f2c7f0519','4936c40f48f1965c14e88d7e72fc83b1','c5a3f26b00b336a8a7b02cbe4c5ff23b']"

  strings:
    $hex_string = "ocument.getElementById('HTML12'), {}, 'displayModeFull'));\n_Widg"

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}