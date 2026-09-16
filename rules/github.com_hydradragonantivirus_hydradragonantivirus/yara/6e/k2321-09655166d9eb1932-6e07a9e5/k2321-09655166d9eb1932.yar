rule k2321_09655166d9eb1932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09655166d9eb1932"
    cluster      = "k2321.09655166d9eb1932"
    cluster_size = "3"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus symmi vbkrypt"
    md5_hashes   = "['4d241c82d47e6bbf57dec1e44f7cfc6c','632f20c01b346873fc3d6e1e4c181ffb','8ec53e2f13024059b1e5c34c83b0ea91']"

  strings:
    $hex_string = { 97 3a 0a 96 f2 90 b9 61 f7 40 fa 38 ac f2 1c ed 33 b4 ba 21 82 cb d5 0b 7f 51 ea 4e 91 9e 55 72 2a e0 32 7e dd 8e 5c 28 22 23 97 50 ee 6b 00 a3 d2 5e 79 3c c0 67 ab 9d eb 99 ad ec 47 77 05 d8 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}