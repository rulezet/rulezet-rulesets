rule j2321_30bb100208001912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.30bb100208001912"
    cluster      = "j2321.30bb100208001912"
    cluster_size = "15"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor cosmicduke razy"
    md5_hashes   = "['19b9a1b577cde16483c2ae52e2b42b15','1e8b2fc531c81b7ede481ab3d44d92cb','fce78b38e8c50dc23e1aebc61ae049f2']"

  strings:
    $hex_string = { 40 69 78 ac e3 ae ee 91 be b1 f1 81 d1 78 a8 b7 25 eb 86 47 c7 4b 1b fa 46 76 0d 97 92 fb 0b db b6 14 36 75 dc b5 7c d7 f0 70 f6 2f 6a bd 5d 77 a9 fc c4 60 7f 36 db de 7a f4 5c c1 5c a3 e4 83 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}