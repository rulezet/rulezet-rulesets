rule o3e9_353b286a9ac36d16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.353b286a9ac36d16"
    cluster      = "o3e9.353b286a9ac36d16"
    cluster_size = "713"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['003fa4cdbedefd85cf1b5b38c8a1faf7','0046e45acfd52e88640bebc3e87c76c3','0707352c15512c426c94a14a6773f568']"

  strings:
    $hex_string = { a6 5e 75 cc 7b e6 7f a2 61 0c 0d d4 ea 20 2c 2e 58 04 5a a7 91 f1 3f b0 90 69 41 9c cd a2 d8 a9 56 7e 87 d7 f8 f9 4a 81 0c 50 97 9a d8 9b 01 1e 9e cf ad 89 2d 9e 4d 7f e9 ac fc 77 83 6f ae e5 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}