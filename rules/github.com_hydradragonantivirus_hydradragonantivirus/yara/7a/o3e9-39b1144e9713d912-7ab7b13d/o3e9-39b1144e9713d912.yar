rule o3e9_39b1144e9713d912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.39b1144e9713d912"
    cluster      = "o3e9.39b1144e9713d912"
    cluster_size = "249"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['0084b7eb77e936ce374f920119782fe2','036a10b8c5cf6b7d1556d3ca9390de85','0faba771d62adc5f28dadbebdf16a199']"

  strings:
    $hex_string = { d7 0f 7d 9b 87 b9 d2 ce a7 9f e8 e2 e4 18 24 c0 7c 92 9e c3 81 e5 61 fb f1 af aa b4 16 3a 5e 58 a3 e7 99 c1 34 5a e9 2d bb 6b 77 50 b2 0c a9 86 ee 88 02 a8 89 29 09 d1 65 7b 94 90 f9 c8 42 fd }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}