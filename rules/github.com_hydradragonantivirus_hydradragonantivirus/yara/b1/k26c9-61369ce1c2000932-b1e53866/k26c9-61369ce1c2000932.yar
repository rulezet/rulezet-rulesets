rule k26c9_61369ce1c2000932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26c9.61369ce1c2000932"
    cluster         = "k26c9.61369ce1c2000932"
    cluster_size    = "551"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "democry malicious ransom"
    md5_hashes      = "['af692f81ee22e678b24c0491fbbbf373af6f0dd0','3867ab656f72ab8dd6a7aeb617beff3327829677','d16bb76a349e5cc76061970df8db7364b11e242a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26c9.61369ce1c2000932"

  strings:
    $hex_string = { 44 20 2b f9 78 15 ff c2 83 fa 0f 76 ec 85 ff 7e 1a 85 f6 74 06 41 83 fb 01 74 10 83 c8 ff 48 83 c4 78 41 5e 41 5d 5f 5e 5d 5b c3 4c 89 64 24 70 66 89 6c 24 42 48 8b cd 4c 89 7c 24 68 ba 0e 00 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}