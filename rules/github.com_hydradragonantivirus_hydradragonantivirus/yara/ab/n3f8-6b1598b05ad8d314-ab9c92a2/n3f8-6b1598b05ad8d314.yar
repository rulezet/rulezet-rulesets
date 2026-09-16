rule n3f8_6b1598b05ad8d314 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.6b1598b05ad8d314"
    cluster         = "n3f8.6b1598b05ad8d314"
    cluster_size    = "34"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "banker androidos gugi"
    md5_hashes      = "['9737fce6649b8940b930713341cea0626595bc93','2e9a8d1d1541d3b6f108216e303efd23c8e6bd2c','40d2c39f8cf4b30143c393b248d829456ce258bc']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.6b1598b05ad8d314"

  strings:
    $hex_string = { 74 56 69 65 77 3b 00 0d 4c 61 73 74 2d 4d 6f 64 69 66 69 65 64 00 0e 4c 61 79 6f 75 74 52 65 73 2e 6a 61 76 61 00 1d 4c 63 6f 6d 2f 62 75 67 73 6e 61 67 2f 61 6e 64 72 6f 69 64 2f 41 70 70 44 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}