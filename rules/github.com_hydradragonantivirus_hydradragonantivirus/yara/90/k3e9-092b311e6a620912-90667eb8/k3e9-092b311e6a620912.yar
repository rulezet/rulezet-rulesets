rule k3e9_092b311e6a620912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.092b311e6a620912"
    cluster      = "k3e9.092b311e6a620912"
    cluster_size = "44"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jeefo hidrag clfcen"
    md5_hashes   = "['11ac349fb5807a3629abd13a364c943f','227c57cd7d1631318b4f842937d92890','872cd53a0ecc31f357cfa0d9247642f3']"

  strings:
    $hex_string = { 6b de 6d d7 6f d3 71 92 73 bc 75 e5 77 eb 79 ee 7b 9c 7d ce 7f f2 81 f1 83 e7 85 eb 87 fb 89 fd 8b ac 8d f4 8f ff 91 04 93 b4 95 ed 97 01 99 08 9b cf 9d d0 9f c0 a1 f5 a3 09 a5 18 a7 1e a9 13 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}