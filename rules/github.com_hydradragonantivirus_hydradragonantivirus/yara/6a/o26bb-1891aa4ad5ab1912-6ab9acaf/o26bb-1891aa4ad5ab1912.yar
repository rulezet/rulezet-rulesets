rule o26bb_1891aa4ad5ab1912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.1891aa4ad5ab1912"
    cluster         = "o26bb.1891aa4ad5ab1912"
    cluster_size    = "17"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious accphish aedbb"
    md5_hashes      = "['4330dffd27665afc9226ecd479f49870efeab4fe','1257372d12c214aea5a69287347e5d7e19967bfb','5e8be61cc53c779e50b8bd431956edec36c47cfc']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.1891aa4ad5ab1912"

  strings:
    $hex_string = { 00 30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}