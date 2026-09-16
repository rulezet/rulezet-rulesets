rule n3f8_492c32adce420912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.492c32adce420912"
    cluster         = "n3f8.492c32adce420912"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "droidkungfu androidos kungfu"
    md5_hashes      = "['7cd9e1bc2b1a646f0f04cb1412050a598fb764f2','2e0c9b82d74a82800046e24f04d77bf7a356a895','8f9d89d8e1f9897a3c4588ecfb9fea115ace20eb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.492c32adce420912"

  strings:
    $hex_string = { 64 77 6f 20 70 75 62 6c 69 73 68 65 72 20 49 44 2e 20 20 53 68 6f 75 6c 64 20 33 32 20 5b 61 2d 7a 2c 30 2d 39 5d 20 63 68 61 72 61 63 74 65 72 73 3a 20 20 00 70 43 4f 4e 46 49 47 55 52 41 54 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}