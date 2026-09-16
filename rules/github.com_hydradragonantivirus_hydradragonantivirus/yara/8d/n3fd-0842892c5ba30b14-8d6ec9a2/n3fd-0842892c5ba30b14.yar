rule n3fd_0842892c5ba30b14 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3fd.0842892c5ba30b14"
    cluster      = "n3fd.0842892c5ba30b14"
    cluster_size = "326"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "browsefox yontoo abde"
    md5_hashes   = "['02b3064f63e45e6828b510e45981e9a7','02dee4afb97b0d4399be246e3eb062f4','0b8f466ec8580f316f466bb51a608c38']"

  strings:
    $hex_string = { 02 26 07 0d 18 11 83 60 11 83 64 11 83 68 0e 08 18 02 09 12 81 b9 15 11 82 e9 01 08 15 11 82 e9 01 08 15 11 82 e9 01 08 0a 07 04 12 81 79 12 84 cd 0e 0e 05 20 00 12 81 81 05 20 00 12 82 6d 03 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}