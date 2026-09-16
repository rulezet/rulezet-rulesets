rule k3e9_691c5e99c6200b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.691c5e99c6200b32"
    cluster      = "k3e9.691c5e99c6200b32"
    cluster_size = "76979"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre waski generickd"
    md5_hashes   = "['00011b0924d7c75ab42184d5f169e0b0','000469467df45c185f93f1ef0335ab64','002f10e3361f617e71459b13fea7fa7e']"

  strings:
    $hex_string = { 41 23 22 ba 36 0a 3f 5b 5f c7 93 d2 0e f4 2e 66 6c ff 24 80 7a 58 b1 8a 47 74 b0 bc 44 f4 25 91 15 c5 20 2b f1 aa a4 bd 06 9d 09 34 dd 5c 86 27 d5 d6 65 3a 16 1e b8 e5 70 b5 e1 71 95 35 0d 11 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}