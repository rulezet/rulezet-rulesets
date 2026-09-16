rule k26bb_5a98487bc964d111 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.5a98487bc964d111"
    cluster         = "k26bb.5a98487bc964d111"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "yontoo browsefox grayware"
    md5_hashes      = "['d27840388d65e871753793056a647b855660ec51','5da88d068dc916c462f2f7fb6751ed671fb38227','bac510dbe04743a99c7d54e0428a2217039f5723']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.5a98487bc964d111"

  strings:
    $hex_string = { 99 6e 83 12 1f ac 81 21 5b 2d fc cf 49 2c db ed 4e 92 7c cb f0 c4 e1 25 88 5e 70 b2 a8 90 5d 3d 8e bb 56 fd a1 98 80 e0 55 7f 41 0c 30 8a 97 33 d8 94 2a d1 84 a5 af c9 87 a2 de 92 65 18 06 e6 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}