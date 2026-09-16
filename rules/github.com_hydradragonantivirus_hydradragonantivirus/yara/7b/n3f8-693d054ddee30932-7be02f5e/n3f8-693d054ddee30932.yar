rule n3f8_693d054ddee30932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.693d054ddee30932"
    cluster         = "n3f8.693d054ddee30932"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "droidkungfu androidos kungfu"
    md5_hashes      = "['74d984cd1640331aa971f5e4fb8018412604646e','c476d29fb1a4224cfb4538120c5949e12ef5727a','e9e6b4d157d0350b3f5d03a9c837f10b8a95f955']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.693d054ddee30932"

  strings:
    $hex_string = { 02 00 ba 83 02 00 d7 83 02 00 f8 83 02 00 12 84 02 00 27 84 02 00 35 84 02 00 40 84 02 00 48 84 02 00 50 84 02 00 64 84 02 00 72 84 02 00 80 84 02 00 e1 84 02 00 ec 84 02 00 01 85 02 00 1b 85 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}