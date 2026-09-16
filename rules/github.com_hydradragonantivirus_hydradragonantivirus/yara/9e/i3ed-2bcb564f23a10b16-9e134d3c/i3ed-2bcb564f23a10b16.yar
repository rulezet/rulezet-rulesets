rule i3ed_2bcb564f23a10b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ed.2bcb564f23a10b16"
    cluster      = "i3ed.2bcb564f23a10b16"
    cluster_size = "102"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "gamarue bundpil zusy"
    md5_hashes   = "['05de719bb23122bd1ad135d74d4c0deb','0b03d8f825c1865c7bcfb80cd57d5eb2','372f8255f1bacd1f9abe0890fca9acc9']"

  strings:
    $hex_string = { 03 55 f4 8a 45 f8 88 02 eb bd 8b e5 5d c3 cc cc cc cc cc cc cc 55 8b ec 8b 45 08 50 e8 64 ff ff ff 83 c4 04 eb 09 8b 4d 08 83 c1 01 89 4d 08 8b 55 08 0f be 02 85 c0 74 0f 8b 4d 08 8a 11 80 c2 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}