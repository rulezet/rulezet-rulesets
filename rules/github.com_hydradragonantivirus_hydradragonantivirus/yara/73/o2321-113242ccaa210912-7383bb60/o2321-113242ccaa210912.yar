rule o2321_113242ccaa210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o2321.113242ccaa210912"
    cluster      = "o2321.113242ccaa210912"
    cluster_size = "13"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr unwanted"
    md5_hashes   = "['11012c29e63913648ca89b9a66a68c63','11c18e5429565398bb80d2af49ff9d30','e468517e52767ece270e542349277018']"

  strings:
    $hex_string = { b3 4b 10 77 74 4a ab 28 88 72 68 80 f1 7f 5a 8a b9 bd 39 4d 9e a7 83 2f 14 0a 4e 53 38 40 e9 42 03 5d f4 0c 43 58 ef 65 c2 f8 e4 f7 5f 06 1a f5 bb fe 6e a0 ac c0 f2 e2 21 cf 97 5b e5 44 0b be }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}