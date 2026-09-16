rule o3e9_153128e29ac3691a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.153128e29ac3691a"
    cluster      = "o3e9.153128e29ac3691a"
    cluster_size = "694"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['00b4418c609897cfd2353cde0fbcbfd7','01e3d8e2de4c0b229163665318fa474c','072bc8f7c8e19aaf3ecced6ac40f0b36']"

  strings:
    $hex_string = { d5 fa 50 75 de 3e b5 c9 48 11 a5 f4 ce a2 16 5c ca 7e 1c 9d 36 83 a8 55 a0 b0 7a 44 f0 5e 65 cf 4b 0f 18 ae 7f 4a c9 05 08 27 4f 62 76 cd 9b 86 cb 0d 01 58 18 29 72 c2 70 fc 30 27 1b 50 ac 50 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}