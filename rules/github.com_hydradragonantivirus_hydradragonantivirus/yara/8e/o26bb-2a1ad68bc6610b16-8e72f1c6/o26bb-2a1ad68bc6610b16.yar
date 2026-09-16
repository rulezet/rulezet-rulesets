rule o26bb_2a1ad68bc6610b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.2a1ad68bc6610b16"
    cluster         = "o26bb.2a1ad68bc6610b16"
    cluster_size    = "186"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious attribute dangerousobject"
    md5_hashes      = "['8e7b3a4518da822fc94775e13c59bb53bcd8ce43','3bffc8a3a17db4481d7e765a69c189f8afdfff74','27bc8e8d5e7f94ceafcd92518b13034b760536c6']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.2a1ad68bc6610b16"

  strings:
    $hex_string = { e2 13 14 c7 ea 20 48 ba 7b d5 f4 9e 47 86 f6 d1 d8 58 4f a8 6c cd 11 27 18 6e ff 36 08 9c 2b 72 96 55 dc f0 30 a5 1f 5e 44 8a 4a b3 80 eb 06 19 89 c2 46 99 32 9d f2 68 0f b4 cf ef a3 76 31 81 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}