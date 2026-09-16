rule pfc8_45b8699ada574b4e {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=pfc8.45b8699ada574b4e"
    cluster         = "pfc8.45b8699ada574b4e"
    cluster_size    = "95"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "fakeapp airpush andr"
    md5_hashes      = "['a18f5c24681f28c2db33c9f481bab09e1d465392','1efda06e127479355976878d5abfebe941b74823','e48f379023312d7e520b83091f11a53b5c2327fd']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=pfc8.45b8699ada574b4e"

  strings:
    $hex_string = { ae 23 87 0f e4 35 e8 af 4f 91 65 b9 09 a7 db 0d 00 5d 80 f7 ff 04 18 97 9b b2 f3 8e aa 3e 29 49 0b 3a bc 4a 48 77 2a bd 41 c8 ce b6 36 86 42 c1 c2 63 9e f5 e1 e2 46 59 6b ea cd 2d 5a 93 d8 5c }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}