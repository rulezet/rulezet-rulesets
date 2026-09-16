rule o2321_219d10b9c8800b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o2321.219d10b9c8800b32"
    cluster      = "o2321.219d10b9c8800b32"
    cluster_size = "39"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "miniduke backdoor cosmicduke"
    md5_hashes   = "['05bc5a21f31659cb624b6c2a9848b434','061b883e70ba7c7796d61048af7b708a','6c426b09a88dcf896fea7ab2b11a3195']"

  strings:
    $hex_string = { 4c 13 0c 2b 4e a1 e0 1f 9d 9c f4 fe af 59 bc 33 53 bf 78 e3 8c a0 d8 a6 45 38 eb b6 86 2f 90 1c 04 b8 76 87 a5 6b c7 ec f1 0f 8e a3 02 b7 df 47 51 1b 49 97 0d 15 de 81 6d 09 c2 3f 79 9a fb ba }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}