rule o3e9_3b1225169da31912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.3b1225169da31912"
    cluster      = "o3e9.3b1225169da31912"
    cluster_size = "6"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mplug multiplug unwanted"
    md5_hashes   = "['2a333a9f508890fcb5cc61b49b1c4851','904cfc38b509640c238a0f84e3cc3896','fbc6257867eb1db8276480e86db68123']"

  strings:
    $hex_string = { ba 43 46 f6 be 47 42 fa b2 4b 4e fe b6 4f 4a e2 aa 53 56 e6 ae 57 52 ea a2 5b 64 d0 98 65 60 d4 9c 69 6c d8 90 6d 68 dc 94 71 74 c0 88 75 70 c4 8c 79 7c c8 cb 30 37 81 cf 34 33 85 c3 38 2e 9d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}