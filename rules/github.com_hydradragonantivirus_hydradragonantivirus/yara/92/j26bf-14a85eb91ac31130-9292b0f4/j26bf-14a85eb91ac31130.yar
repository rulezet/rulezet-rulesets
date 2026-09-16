rule j26bf_14a85eb91ac31130 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26bf.14a85eb91ac31130"
    cluster         = "j26bf.14a85eb91ac31130"
    cluster_size    = "173"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious onlinegames"
    md5_hashes      = "['687ddebf28532bc48f84eb70eacfa2f696175293','31ef4ecc3333b71993ee8ff23fb8e844fbaa288d','537aaef6136a10ffcee2600ec3f797deb331f5c0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26bf.14a85eb91ac31130"

  strings:
    $hex_string = { 11 15 75 19 00 00 01 13 17 11 17 2c 07 11 17 6f 25 00 00 0a dc 11 14 17 58 13 14 11 14 11 13 8e 69 3f 8f fe ff ff 08 39 79 fe ff ff dd 5b 02 00 00 26 1f 1c 28 26 00 00 0a 72 93 03 00 70 73 20 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}