rule k2321_03959a50c8827916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.03959a50c8827916"
    cluster      = "k2321.03959a50c8827916"
    cluster_size = "8"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "regrun ludbaruma rontokbro"
    md5_hashes   = "['1d585ad68b98316d4247194c751a8859','2e4b55d21503c61f1882ffebc0e219f9','b8d482a9fd68eadbc8314c4eec774252']"

  strings:
    $hex_string = { dd a3 46 77 e8 5b 22 6a 74 aa db 2b b4 f5 f0 4c f3 f1 1d da d2 9e 65 18 d5 4f af ce 26 36 c0 8b 33 4b 08 24 a0 0d cb c6 ac bc 50 61 55 7a 52 56 f6 c2 7b 33 eb 29 ed 9d d9 c4 1a 78 63 66 89 5a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}