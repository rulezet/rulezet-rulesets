rule k3e9_072ca619c2929932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.072ca619c2929932"
    cluster      = "k3e9.072ca619c2929932"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor berbew peed"
    md5_hashes   = "['05ce800209b916ae3bf95402f59a0290','1c6ba397531de3079d3d5bc240cb92d5','d124bb5b6ef25778a524c31cd51e1b82']"

  strings:
    $hex_string = { 73 73 41 00 00 00 00 93 02 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 00 00 00 97 02 57 69 64 65 43 68 61 72 54 6f 4d 75 6c 74 69 42 79 74 65 00 00 00 98 02 57 69 6e 45 78 65 63 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}