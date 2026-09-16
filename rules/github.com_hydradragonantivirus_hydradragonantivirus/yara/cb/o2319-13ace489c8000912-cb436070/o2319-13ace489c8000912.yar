rule o2319_13ace489c8000912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.13ace489c8000912"
    cluster         = "o2319.13ace489c8000912"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "script coinminer miner"
    md5_hashes      = "['96bf1630795b8a94c3024e4ea34d19d60c88e169','cb793e5098c24b127e513dc6824de90c718a4ee3','4444527c72dcc60ed0fe58a1214764f909f36853']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.13ace489c8000912"

  strings:
    $hex_string = "g[ad]+'\" />'}}aa.outerHTML='<object classid=\"clsid:D27CDB6E-AE6D"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}