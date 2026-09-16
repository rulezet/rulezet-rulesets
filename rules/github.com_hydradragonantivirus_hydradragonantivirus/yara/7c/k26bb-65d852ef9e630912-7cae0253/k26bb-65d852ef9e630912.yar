rule k26bb_65d852ef9e630912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.65d852ef9e630912"
    cluster         = "k26bb.65d852ef9e630912"
    cluster_size    = "398"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "adwaresail ejtxwd heuristic"
    md5_hashes      = "['af227198d42a5494e85754c67c2fddd4656d86ef','2e7cdd2f6fec6ad91e21cf1c36eb3f315ef6f7ef','df4fb8a6094938fbb83758b97f929d0d70669afa']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.65d852ef9e630912"

  strings:
    $hex_string = { 68 5c a5 40 00 50 ff 15 ec 80 40 00 83 c7 0a eb 35 83 c0 0a 68 58 a5 40 00 50 e8 f9 fc ff ff 8b e8 85 ed 74 1d 8d 0c 3e 8d 04 19 eb 06 8a 11 88 10 48 49 3b cd 77 f6 2b ee 45 8b c5 8b 6c 24 18 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}