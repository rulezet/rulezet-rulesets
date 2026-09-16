rule k2321_0910dca6dfa31932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0910dca6dfa31932"
    cluster      = "k2321.0910dca6dfa31932"
    cluster_size = "4"
    filetype     = "PE32 executable (console) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hupigon backdoor razy"
    md5_hashes   = "['0884b31632640b4b69b0d18b0346ca93','36a2b7d6a521bfb0499d3b19fd93dc02','e562b8acb3f3e47c28c146f472fb190e']"

  strings:
    $hex_string = { 48 b3 30 20 3a 92 a5 5d 16 1f 98 c4 78 88 94 75 fa de f2 62 8e ac dd 53 89 74 52 21 34 61 5a 09 e5 d7 2d 69 14 d9 0e 18 52 2b e8 d8 a6 a4 72 5c 3e 32 a3 a0 95 be 8e c6 e1 36 bd 9a 83 51 4a 6f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}