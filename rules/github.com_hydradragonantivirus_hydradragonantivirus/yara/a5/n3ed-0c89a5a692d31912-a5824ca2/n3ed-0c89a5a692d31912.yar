rule n3ed_0c89a5a692d31912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3ed.0c89a5a692d31912"
    cluster      = "n3ed.0c89a5a692d31912"
    cluster_size = "20"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit nimnul bmnup"
    md5_hashes   = "['079762ae01bcf3a4986b433270350680','0b79e540c82fea6ac85a528d76d23a7e','ea8baff2ed305805a5f455d6b538366c']"

  strings:
    $hex_string = { 73 77 74 5f 69 6e 74 65 72 6e 61 6c 5f 77 69 6e 33 32 5f 4f 53 5f 4e 4d 52 45 42 41 52 43 48 49 4c 44 53 49 5a 45 5f 31 73 69 7a 65 6f 66 40 38 00 5f 4a 61 76 61 5f 6f 72 67 5f 65 63 6c 69 70 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}