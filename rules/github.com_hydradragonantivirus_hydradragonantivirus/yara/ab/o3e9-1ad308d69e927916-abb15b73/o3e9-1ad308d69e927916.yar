rule o3e9_1ad308d69e927916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.1ad308d69e927916"
    cluster      = "o3e9.1ad308d69e927916"
    cluster_size = "325"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['0005eba20e8a13ee0af7588b08503214','00b263e4ee33c9f443666956a9308842','0be9897074cf7e9c37a364c8fee366ba']"

  strings:
    $hex_string = { af 49 dc 97 df dd 49 df b8 5e c4 a6 5c 48 da 87 88 50 c4 7f 8e 1c 84 58 50 4e c2 35 30 5d 61 dc 2e 10 9a c5 e9 53 11 7c 3c 19 5c ac ed f2 b9 ca 4c 8e 4d 0f 91 92 50 9a f0 1e f3 d1 94 b0 8a f5 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}