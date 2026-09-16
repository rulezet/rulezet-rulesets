rule n3f8_5c94fac1c8000130 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.5c94fac1c8000130"
    cluster         = "n3f8.5c94fac1c8000130"
    cluster_size    = "145"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "banker androidos asacub"
    md5_hashes      = "['cd0f5ce5d371cdbfcadaa326aee8d86a045b6016','5e3a07977c09e1d92a92628cb486c5feebb11d75','cf4aac1ff0a3e7fe90d40780f3cf3a8718cf2ed4']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.5c94fac1c8000130"

  strings:
    $hex_string = { 50 69 6e 67 3b 00 34 4c 63 6f 6d 2f 73 71 75 61 72 65 75 70 2f 6f 6b 68 74 74 70 2f 69 6e 74 65 72 6e 61 6c 2f 66 72 61 6d 65 64 2f 50 75 73 68 4f 62 73 65 72 76 65 72 24 31 3b 00 32 4c 63 6f }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}