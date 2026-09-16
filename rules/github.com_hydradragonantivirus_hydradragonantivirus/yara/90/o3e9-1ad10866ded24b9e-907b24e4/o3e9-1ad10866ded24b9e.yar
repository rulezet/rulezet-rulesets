rule o3e9_1ad10866ded24b9e {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.1ad10866ded24b9e"
    cluster      = "o3e9.1ad10866ded24b9e"
    cluster_size = "605"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['0009c0d0a49905a03f9d70818abcf089','0019d6fc5cf067e92884eaa7030013e0','05a71f7a160d3d05ccf44b8ff0ac2888']"

  strings:
    $hex_string = { a7 5b 03 8e 1e fc 9f 8e 89 a8 01 ac da bc f5 a9 55 01 b9 3e 4d b2 59 46 ae fb c5 a0 39 74 74 37 68 5a 76 9b 69 8c b3 df 17 f7 23 27 c3 28 96 81 cf 1f 04 fe c1 f0 34 be 19 01 13 67 ff 59 09 f3 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}