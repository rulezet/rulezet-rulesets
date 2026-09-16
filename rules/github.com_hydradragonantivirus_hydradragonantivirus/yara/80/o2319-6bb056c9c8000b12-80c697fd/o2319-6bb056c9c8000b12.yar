rule o2319_6bb056c9c8000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.6bb056c9c8000b12"
    cluster         = "o2319.6bb056c9c8000b12"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "script miner coinminer"
    md5_hashes      = "['37e4860452e142fa405e9d8e526934d36d5d66f3','2ae41e650d527163958b0374d914b0f0d1c47762','7fe955638b414280c35f0d9e6520e7c3c2c00682']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.6bb056c9c8000b12"

  strings:
    $hex_string = "pply(window,[].slice.call(arguments,0))};\r\n\n/* <![CDATA[ */\nvar "

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}