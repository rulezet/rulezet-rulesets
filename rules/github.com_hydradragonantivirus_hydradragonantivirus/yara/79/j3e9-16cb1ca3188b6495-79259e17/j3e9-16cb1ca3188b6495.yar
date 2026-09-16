rule j3e9_16cb1ca3188b6495 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.16cb1ca3188b6495"
    cluster      = "j3e9.16cb1ca3188b6495"
    cluster_size = "15"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "madangel small madang"
    md5_hashes   = "['1c289da1e9873f617b5117ba36ba2a74','56c8f7bc3f2fd457a694e03b34ce9c43','fce3e537be1abee5df851f2e88c8f626']"

  strings:
    $hex_string = { 66 81 3e 4d 5a 78 03 79 01 eb 75 ee 0f b7 7e 3c 03 fe 8b 6f 78 03 ee 8b 5d 20 03 de 33 c0 8b d6 83 c3 04 40 8b 3b 03 fa e8 0f 00 00 00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 5e 33 c9 b1 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}