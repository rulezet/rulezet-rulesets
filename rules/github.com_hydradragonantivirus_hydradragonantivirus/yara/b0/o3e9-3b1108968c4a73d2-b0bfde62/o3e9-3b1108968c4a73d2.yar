rule o3e9_3b1108968c4a73d2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.3b1108968c4a73d2"
    cluster      = "o3e9.3b1108968c4a73d2"
    cluster_size = "837"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['0009fd6c1337942f2eb9204a31385b50','00116121cce3a7205e469141466530a9','0438c07ff35671e9fb7381db610877ca']"

  strings:
    $hex_string = { 94 5a 1c 66 7f f9 7d c2 7e d5 78 44 71 dc 40 e9 52 84 14 e9 1d c0 19 ca f3 af 28 1f 6b 9d 28 c8 5a 1d 9d 20 0e d8 d7 d1 1c 9c be c5 dc 5a 1e 35 6d 21 2d ed 0f 08 de 58 cf ca 4c 9b 42 80 44 1c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}