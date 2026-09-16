rule o3e9_2d1268d296927992 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.2d1268d296927992"
    cluster      = "o3e9.2d1268d296927992"
    cluster_size = "50"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['025b204e2a39eeff123c60a8805bd6c4','04346d58b0ca8b867815a07f1459ed64','4076edf53928433919ee579362baa829']"

  strings:
    $hex_string = { 80 19 b2 9c c3 ba 60 58 8c 1c 7e d1 07 35 51 a5 50 dd 4f e3 66 eb d7 55 38 93 47 ff 65 4a 25 a0 b8 b4 e2 97 3e 18 a7 20 32 68 1f e1 be 3d bf 6f d4 c2 75 cf fa 1e 67 52 36 33 87 69 b3 28 5e 7d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}