rule o3e9_2a4620a529495446 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.2a4620a529495446"
    cluster      = "o3e9.2a4620a529495446"
    cluster_size = "2250"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "graftor speedingupmypc advml"
    md5_hashes   = "['0042c2c5a0a86ab5c5ae94623d855114','004c95c1cc903e3b308270e995291529','012abebc5b21045e4e08453d3c708cb4']"

  strings:
    $hex_string = { e8 1d 80 8f 9b 30 92 27 d3 c0 1d b4 23 fd 7d 4f e6 84 a4 2d a7 b1 f6 13 0c 20 58 c2 c0 a9 e3 2b 98 36 8e 76 68 58 51 db 71 ca 10 19 ca 98 cc 99 fc 80 c3 71 f9 75 23 ac 58 30 73 5c b8 1e 4e 70 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}