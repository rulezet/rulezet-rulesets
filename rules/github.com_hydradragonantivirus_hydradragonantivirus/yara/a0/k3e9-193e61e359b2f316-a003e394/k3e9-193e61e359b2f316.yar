rule k3e9_193e61e359b2f316 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.193e61e359b2f316"
    cluster      = "k3e9.193e61e359b2f316"
    cluster_size = "95"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installcore dealply malicious"
    md5_hashes   = "['00d71f31ab5da9338821c60d136cc663','040ddb228b7b0822c633fdbdccabef64','34b6b1f2d05d9522e7285c2112885d72']"

  strings:
    $hex_string = { 9c 09 06 f0 fb 78 a9 5c 8b bc 67 88 e0 4e 30 87 f9 94 db 49 c2 53 15 38 19 58 ba 75 8c 2f 80 af 22 77 1f 47 65 6b d2 1a c1 a7 e2 52 3f f7 76 cc d8 34 c0 54 1b d5 44 f5 24 40 33 99 14 21 2a ce }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}