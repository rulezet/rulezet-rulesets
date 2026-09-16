rule k3e9_69d09ce918eb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.69d09ce918eb0b12"
    cluster      = "k3e9.69d09ce918eb0b12"
    cluster_size = "237"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mywebsearch toolbar riskware"
    md5_hashes   = "['00e38b11581b2354d5e82dcccb285076','01887be544e1fd5e6f0767bf274354a3','0f7c7d70c27f608070729d83c93e6b49']"

  strings:
    $hex_string = { 2a 32 4a f7 1a a5 fd fb 65 bd ef a3 04 7b 78 83 7e 52 a7 b4 d8 20 19 1e 90 66 6e 95 0a 91 ee 33 24 b7 51 29 34 ed ff 58 6f 77 9b 36 18 7c 35 26 ae 28 50 68 11 e9 4d c1 9a c2 6a f0 72 c0 bf 57 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}