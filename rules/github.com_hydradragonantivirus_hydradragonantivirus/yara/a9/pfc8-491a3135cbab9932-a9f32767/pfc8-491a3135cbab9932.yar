rule pfc8_491a3135cbab9932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=pfc8.491a3135cbab9932"
    cluster         = "pfc8.491a3135cbab9932"
    cluster_size    = "45"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "apptrack riskware andr"
    md5_hashes      = "['106e6a50561677eea0ebc868dc48b06ba7123f2e','10209f5702f7a5893c60033a07e07fdab193b257','5414b9f87c686b3e4a26dd60590ada7581498bc2']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=pfc8.491a3135cbab9932"

  strings:
    $hex_string = { c3 fb c5 db 94 15 8c 49 10 9b 9f 1d 73 8b c0 4c 16 57 38 c2 47 9c 2e f6 c7 65 67 0d 06 4f 2d 3a da 30 83 3f 75 dc b2 95 6c d0 b6 81 72 2c 31 ea 51 8f 11 07 a3 37 d6 c8 a5 04 68 b5 26 b4 c9 6e }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}