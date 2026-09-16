rule k2318_258f16e9c8800912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2318.258f16e9c8800912"
    cluster         = "k2318.258f16e9c8800912"
    cluster_size    = "341"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "iframe html redirector"
    md5_hashes      = "['3fa332b0ec8ccb738bcf6ed12e6b2491caaa0840','156bc045b8d721bd8b41d7c4092f4d29ac03200b','c0a2fff00e474f0d1851e134358c94f37fe62470']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2318.258f16e9c8800912"

  strings:
    $hex_string = { 72 79 2f 69 6e 64 65 78 2e 70 68 70 3f 63 50 61 74 68 3d 33 33 22 3e e3 ee ec e5 ee ef e0 f2 e8 f7 e5 f1 ea e8 e5 20 ef f0 e5 ef e0 f0 e0 f2 fb 3c 2f 61 3e 26 6e 62 73 70 3b 28 31 31 29 3c 62 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}