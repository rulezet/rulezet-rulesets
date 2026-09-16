rule j3f4_090ee938c2200b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f4.090ee938c2200b32"
    cluster      = "j3f4.090ee938c2200b32"
    cluster_size = "21"
    filetype     = "PE32 executable (GUI) Intel 80386 Mono/.Net assembly"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "razy malicious agbf"
    md5_hashes   = "['27faa1c75f5fdfd93eac3bd1c4e84771','29620545fd65aab0de7e0edc855e8eb4','a26835a850f65c89d5fd13ac147f822c']"

  strings:
    $hex_string = { 00 00 4d d1 f2 ff 4c d0 f1 ff 4c cf f1 ff 4c cf f0 ff 4c ce f0 ff 4b cd ef ff 4b cd ef ff 4b cc ef ff 4a cb ee ff 4a cb ee ff 4a ca ed ff 49 c9 ed cf 00 00 00 00 00 00 00 00 c0 01 00 00 c0 01 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}