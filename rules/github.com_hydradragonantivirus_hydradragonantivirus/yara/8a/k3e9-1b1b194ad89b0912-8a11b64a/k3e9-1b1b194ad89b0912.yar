rule k3e9_1b1b194ad89b0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1b1b194ad89b0912"
    cluster      = "k3e9.1b1b194ad89b0912"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vbkrypt injector symmi"
    md5_hashes   = "['02df15de5bdd5e9be466c89ce755d0a8','4e16d9171d257a348261805afcb004f3','feff7ec8fa0bae9eddcad4cdbfea01e8']"

  strings:
    $hex_string = { 1f 95 d1 25 e2 c6 2f 3a 94 55 de 4f 79 fd 82 bd af 17 3c b2 45 5c c4 36 ed b1 61 0e 7b 74 e7 ae 58 5f c2 aa a1 5a fb 99 e3 f0 5b c7 41 15 03 da 35 53 9e 32 72 5d 9f 12 b8 a7 6a 8a 8d 62 8f 34 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}