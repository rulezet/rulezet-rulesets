rule p26bb_2b0f1ac1c4000912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26bb.2b0f1ac1c4000912"
    cluster         = "p26bb.2b0f1ac1c4000912"
    cluster_size    = "42"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "mdeclass bscope cmrtazq"
    md5_hashes      = "['689e00f0b53da89d260c63b4f68996862a34489f','dc4a02ebe023060e87e4951564af014cb06bf3d6','500c2921d956d7f79bb0214f2957eb8f5ccf9fc3']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26bb.2b0f1ac1c4000912"

  strings:
    $hex_string = { 03 f8 45 46 3b f3 72 dc 51 8b 4c 24 14 2b 31 56 e8 67 7b ee ff 85 ed 74 0a 8b 44 24 14 89 38 b0 01 eb 02 32 c0 5f 5e 5d 5b 59 59 c3 b8 ae 9b 72 00 e8 88 5a 1a 00 83 ec 10 56 57 8b f9 8d 77 08 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}