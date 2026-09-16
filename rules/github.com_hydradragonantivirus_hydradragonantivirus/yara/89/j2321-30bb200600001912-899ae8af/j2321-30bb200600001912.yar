rule j2321_30bb200600001912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.30bb200600001912"
    cluster      = "j2321.30bb200600001912"
    cluster_size = "8"
    filetype     = "gzip compressed data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmicduke backdoor razy"
    md5_hashes   = "['01f01d00365804f1eb80a3b5aa792d4f','08de74765f870d5005a37cd12a57035a','bfd606c12764a142e92361759ba4d33f']"

  strings:
    $hex_string = { f7 57 66 cf da a1 eb b3 4f 45 7c 2b 6c 8f 8b d9 86 98 6d 75 76 f5 a9 b4 75 c7 ec b7 63 03 1f aa 9e cb ef c6 a6 fc ee be b9 a3 f6 e6 c0 8a 4a b6 ee 81 28 58 95 37 4d 67 1e dd f9 c5 87 5f 6e c9 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}