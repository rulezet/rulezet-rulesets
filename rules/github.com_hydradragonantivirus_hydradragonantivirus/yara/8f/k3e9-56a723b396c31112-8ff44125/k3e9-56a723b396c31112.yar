rule k3e9_56a723b396c31112 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.56a723b396c31112"
    cluster      = "k3e9.56a723b396c31112"
    cluster_size = "811"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "unruy cycler clicker"
    md5_hashes   = "['0013fceed930e80b621d5d62064ce64c','002e7f6710c6465ef249524e1de2803e','0e425cafe1e59620674f586b7b0fede4']"

  strings:
    $hex_string = { 00 2b 28 aa a5 5d ad 01 7c 97 b2 0e 21 e9 3e 24 f0 84 93 ef 6f a8 83 4b 18 b8 75 52 ac 3d 5b 7f cb 2e e4 13 c2 f2 a4 4e 65 9c f6 9b 81 d7 88 ab 02 4a 79 05 85 1f 64 b4 1a d3 17 ae 0f c0 a3 c9 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}