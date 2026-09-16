rule j3e9_46b25c99c6220912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.46b25c99c6220912"
    cluster      = "j3e9.46b25c99c6220912"
    cluster_size = "9"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor poison poisonivy"
    md5_hashes   = "['97da683e7c0ac875a9919bc7d3627a4e','a1cac5b71c982017660b2fac497bcd38','ded59a8974b8110e94db4c3f4e49d9cf']"

  strings:
    $hex_string = { 5e c5 0b 1a a6 e1 39 ca d5 47 5d 3d d9 01 5a d6 51 56 6c 4d 8b 0d 9a 66 fb cc b0 2d 74 12 2b 20 f0 b1 84 99 df 4c cb c2 34 7e 76 05 6d b7 a9 31 d1 17 04 d7 14 58 3a 61 de 1b 11 1c 32 0f 9c 16 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}