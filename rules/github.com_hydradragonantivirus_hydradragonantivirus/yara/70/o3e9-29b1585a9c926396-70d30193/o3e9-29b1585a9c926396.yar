rule o3e9_29b1585a9c926396 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.29b1585a9c926396"
    cluster      = "o3e9.29b1585a9c926396"
    cluster_size = "1153"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['005a5cb34d6e38daf4e840847b001c8f','01067ddd53a5c23b872772dab1762a36','04122fe6a29cb5db4dbfa66d617dc34d']"

  strings:
    $hex_string = { c8 73 e7 35 27 1b fa d3 cd 9c bf b9 76 5f 7c e6 93 cd 9b 91 9e 2a 1e 36 dc ee 2a 96 a4 09 47 02 83 f6 96 64 30 65 a6 a1 35 3b 6d 4c a2 79 f8 3b 75 27 f4 2a 97 45 6b 2b a1 21 03 c5 e4 c9 f6 8d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}