rule o3e9_6130d4a2ca000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.6130d4a2ca000b12"
    cluster      = "o3e9.6130d4a2ca000b12"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious kryptik filerepmalware"
    md5_hashes   = "['244ee4d2c94f8f6a167d5123fe4a3d1d','3d5b312a23d25b6be98dfe402a733aee','fc56c66b9efb2020ab30ef8a2bf8a29b']"

  strings:
    $hex_string = { 00 00 00 00 0f 39 7e 00 12 3a 7b 01 08 37 84 05 0f 3a 7e 0f 18 3e 7d 2b 2a 4b 7d 8f 2a 4e 88 fb 1a 3a 74 ff 16 30 63 ff 26 50 93 ff 22 48 8a ff 1f 43 84 ff 3a 67 a6 d5 2d 4d 7f 42 29 43 6d 0d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}