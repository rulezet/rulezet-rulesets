rule j2319_039a44acd2930932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j2319.039a44acd2930932"
    cluster         = "j2319.039a44acd2930932"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "megasearch megasearchplugin plugin"
    md5_hashes      = "['b80dc3b4f63ee5ce817723945afac54cbba9a0f3','9e4e37c6a8496ade51fba1dd873873762e0ca35f','c566af26cff0c9845441a2b732a37d1b3cecf21e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j2319.039a44acd2930932"

  strings:
    $hex_string = ".getTime()/1E3)}}catch(c){return 0}}},dbclass={engines:[\"prfdb\","

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}