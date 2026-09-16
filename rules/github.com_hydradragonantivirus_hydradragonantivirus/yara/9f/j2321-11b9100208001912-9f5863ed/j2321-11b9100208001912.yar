rule j2321_11b9100208001912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.11b9100208001912"
    cluster      = "j2321.11b9100208001912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor cosmicduke razy"
    md5_hashes   = "['1ce881864c9bc5b711f3dc2533f8bef6','5ac6c87f29f1a9da95666cf44b0acb91','cd238336c76c9948621d8757c17bf427']"

  strings:
    $hex_string = { f7 57 66 cf da a1 eb b3 4f 45 7c 2b 6c 8f 8b d9 86 98 6d 75 76 f5 a9 b4 75 c7 ec b7 63 03 1f aa 9e cb ef c6 a6 fc ee be b9 a3 f6 e6 c0 8a 4a b6 ee 81 28 58 95 37 4d 67 1e dd f9 e5 87 5f 6e c9 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}