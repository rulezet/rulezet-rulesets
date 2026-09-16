rule o2319_39e76a49c0000932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.39e76a49c0000932"
    cluster         = "o2319.39e76a49c0000932"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "cryxos coinminer coinhive"
    md5_hashes      = "['86c3c3fc3ff0d48d071b0408a75019713d58783e','d278542be1ed3f0675da78ceed6fa32b27710425','ed3f990b765a56d6b0b08375d02fd4fa5a5ca4f9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.39e76a49c0000932"

  strings:
    $hex_string = "find.TAG(\"*\",c&&s.parentNode||s),w=$+=null==x?1:Math.E;for(b&&(j"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}