rule k3e9_063cae1b92e39912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.063cae1b92e39912"
    cluster      = "k3e9.063cae1b92e39912"
    cluster_size = "7"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "qukart backdoor berbew"
    md5_hashes   = "['6b0ebcbb4d8f3e078031176e003e6a02','c6b3f96066d99998f740d7aa12abd548','ef382a9dfd2c31f9ac2be3d98f618538']"

  strings:
    $hex_string = { a3 c2 8b ff d2 fc f7 bd 2a 70 21 aa 12 1c 08 42 90 c7 9f 59 48 55 81 83 dd ee c9 b8 2d c5 f1 5d 03 ce 81 92 73 8d cf 05 11 b9 f0 ba d5 fb 07 c5 65 06 08 42 a9 39 68 df 6b 04 0a 37 1d 6c 98 e3 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}