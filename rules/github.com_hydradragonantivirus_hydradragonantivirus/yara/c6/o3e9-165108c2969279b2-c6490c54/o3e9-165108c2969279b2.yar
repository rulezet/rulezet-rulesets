rule o3e9_165108c2969279b2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.165108c2969279b2"
    cluster      = "o3e9.165108c2969279b2"
    cluster_size = "1254"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonstr installmonster malicious"
    md5_hashes   = "['0000543253e0f3dc9cfa4255ce887ea3','000afff09f07f65369335066ba5a51e7','02e7620dda4826f832ae5ba02fbe4e54']"

  strings:
    $hex_string = { 08 69 0a b6 cb 2f 9f c5 71 83 d8 4d 09 5c 60 19 c0 75 7d 59 2e 1c 5d 40 de a1 24 40 77 a2 01 34 4f 77 e5 dc db b9 08 fc 80 48 89 bc 8f c4 51 b0 b6 6c 51 89 d5 dd fb 33 66 57 98 f0 a2 c8 60 cc }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}