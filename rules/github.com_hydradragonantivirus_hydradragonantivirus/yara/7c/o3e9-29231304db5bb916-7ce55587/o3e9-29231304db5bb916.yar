rule o3e9_29231304db5bb916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.29231304db5bb916"
    cluster      = "o3e9.29231304db5bb916"
    cluster_size = "930"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['001d5f54d9675dc82ca96e99f3cace99','008cb6c962e6cd1fe9b10cc4c109ce57','04d8caabecfd2fd392ba94d35c8c3e5b']"

  strings:
    $hex_string = { 60 a3 58 21 46 d1 4a 10 29 c9 2d 9f 33 02 a9 fa d4 be 92 ea 07 39 17 1c 68 af 49 06 74 ac 2e ef f3 dc 7f 38 20 5f 6d fd a0 fb 6b 75 ed ec ce a5 3a ae d3 f5 de e3 b9 28 63 84 6a 3d 7a 3b 80 a2 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}