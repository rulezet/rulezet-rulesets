rule n3f8_483e854e6a000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.483e854e6a000b12"
    cluster         = "n3f8.483e854e6a000b12"
    cluster_size    = "488"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "sandr androidos kasandra"
    md5_hashes      = "['b562c3cc7dc1c01086c0ecb682f87ce841fc6478','6a23dae6173e664eb3272e6a18b14b443b265183','b5bedc56e8e126fbcbe1c4b8e3bde302e5475e9b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.483e854e6a000b12"

  strings:
    $hex_string = { 74 4b 65 79 53 70 65 63 3b 00 18 4c 6d 7a 63 62 4f 50 67 52 74 61 64 41 39 32 4c 63 4a 6c 55 69 51 3d 3d 00 23 4c 6e 65 74 2f 64 72 6f 69 64 6a 61 63 6b 2f 73 65 72 76 65 72 2f 43 61 6c 6c 4c }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}