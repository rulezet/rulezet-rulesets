rule n3ed_11e9169f46221112 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3ed.11e9169f46221112"
    cluster      = "n3ed.11e9169f46221112"
    cluster_size = "68"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit nimnul bmnup"
    md5_hashes   = "['022467cce16d05badda885169b17dd23','0351ca6ce0f1ea03b8b7e9862e378f2c','4b0cb9efeeb1b840e4b689b513ce2793']"

  strings:
    $hex_string = { 7e 29 8d 49 00 8b e8 66 8b 19 66 01 1c 41 0f b7 19 81 e3 ff 07 00 00 8a 1c 3b 4d 88 1e 83 c1 02 46 85 ed 7f e2 2b d0 85 d2 7f da 5d 5b 5e 83 c4 0c c3 cc cc cc 83 ec 34 dd 05 18 09 04 10 53 55 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}