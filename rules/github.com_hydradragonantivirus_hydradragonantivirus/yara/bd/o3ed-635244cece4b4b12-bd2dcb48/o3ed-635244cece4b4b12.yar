rule o3ed_635244cece4b4b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3ed.635244cece4b4b12"
    cluster      = "o3ed.635244cece4b4b12"
    cluster_size = "518"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit nimnul bmnup"
    md5_hashes   = "['00cb96b50807b3f65279372988798cf1','02396e0d3323bc5d234f385bd48075a9','1848b115a3c37c8eb1862c50e422454e']"

  strings:
    $hex_string = { e9 9a 14 fc ff 8d 4d f0 e9 07 d5 f3 ff 8b 54 24 08 8d 42 0c 8b 4a ec 33 c8 e8 bf 17 fc ff b8 e0 b4 54 53 e9 77 14 fc ff 8d 4d f0 e9 e4 d4 f3 ff 8b 54 24 08 8d 42 0c 8b 4a ec 33 c8 e8 9c 17 fc }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}