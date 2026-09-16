rule k3e9_0234ae1b92bb9912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0234ae1b92bb9912"
    cluster      = "k3e9.0234ae1b92bb9912"
    cluster_size = "8"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "qukart genpack backdoor"
    md5_hashes   = "['87f7ff67b1bbf4fa8bf844666018f624','ac52a1c9bf9a21ac65fe2ed1c041ad5c','c3a0f86e0222d40e91b4dce2c20c3c6d']"

  strings:
    $hex_string = { 63 65 73 73 41 00 00 00 00 93 02 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 00 00 00 97 02 57 69 64 65 43 68 61 72 54 6f 4d 75 6c 74 69 42 79 74 65 00 00 00 98 02 57 69 6e 45 78 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}