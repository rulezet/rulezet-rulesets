rule o3e9_19b158eb14714cf3 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.19b158eb14714cf3"
    cluster      = "o3e9.19b158eb14714cf3"
    cluster_size = "740"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['001ce911265eb93c8443f75333ccf288','002e9f550b2dac19923ec70d2bd17c09','063a7e067bfaa8d0b407b59d66e3c5a2']"

  strings:
    $hex_string = { 33 96 9c 37 56 8a de 24 c6 96 ef 8d 96 89 b4 1e 8b db f8 64 68 c6 6e c0 6a f5 8e 1d d2 ed 00 34 3a 62 e8 54 90 13 6a 2c 51 74 bd df 69 e4 53 36 ab 77 98 99 fa 9c 52 bf dd 37 94 0a d3 d3 02 ca }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}