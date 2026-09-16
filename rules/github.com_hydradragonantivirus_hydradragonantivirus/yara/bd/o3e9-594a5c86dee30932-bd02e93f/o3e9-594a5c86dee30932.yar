rule o3e9_594a5c86dee30932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.594a5c86dee30932"
    cluster      = "o3e9.594a5c86dee30932"
    cluster_size = "69"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dealply bundler malicious"
    md5_hashes   = "['07cf5234ccc977bec80172162fd2d4cf','0b32542124b5db953d4267b6212c5c31','4200ae8a165550a9e070572499243623']"

  strings:
    $hex_string = { 00 28 00 2e 00 25 00 73 00 29 00 1c 00 55 00 6e 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 65 00 64 00 20 00 63 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 20 00 66 00 6f 00 72 00 6d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}