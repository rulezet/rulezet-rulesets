rule o3e9_31686ba1ca000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.31686ba1ca000912"
    cluster      = "o3e9.31686ba1ca000912"
    cluster_size = "4694"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "downloadsponsor malicious unwanted"
    md5_hashes   = "['0001bcac20ff1133965fca7dbf7ef1dd','00072a2f033cd9ff0b57addafa45c4d7','00cc8c7d315fc4e86d74941443d22032']"

  strings:
    $hex_string = { 4d 7b 52 4f 4a d1 4e f3 81 5a 28 9e 10 ac f8 bc 54 8f 6c 28 c5 4f 5b f1 23 55 c5 2e c0 41 71 2a a1 e0 d3 23 55 ee aa 74 3a 98 c9 de 47 27 ae 9a d3 60 13 8f 0e 6a fa 51 25 86 92 50 8b d0 44 89 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}