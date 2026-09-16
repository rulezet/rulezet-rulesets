rule k3e9_0ab24d36dabb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0ab24d36dabb1912"
    cluster      = "k3e9.0ab24d36dabb1912"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "graftor malicious genmalicious"
    md5_hashes   = "['04bacc50e8e78dc946f2d2a6080dd236','2a085f05273d637d8c5f51e61e8fd268','860e21698099b6ced257d193ea03de74']"

  strings:
    $hex_string = { 5b d0 50 61 e1 03 65 f6 5f c9 f8 cd c3 f0 05 2e bd a0 8d 13 04 ac cb 6d a5 e4 86 7a 74 1a 26 6e 35 23 08 99 18 a8 0e 77 42 6c 4d 15 3e 3c e1 0a c4 2a b7 f1 56 fa 11 75 1f 8f b6 cf b0 ca c2 92 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}