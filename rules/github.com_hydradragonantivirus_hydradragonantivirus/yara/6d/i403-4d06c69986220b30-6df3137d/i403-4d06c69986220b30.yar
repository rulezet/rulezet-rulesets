rule i403_4d06c69986220b30 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i403.4d06c69986220b30"
    cluster      = "i403.4d06c69986220b30"
    cluster_size = "400"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rootkit small zusy"
    md5_hashes   = "['02491cc14bc06e581e9fd2055c690ade','026f5d307ee839c013c90ae439569a8f','0ac33efbf469e76c251b6647be0484e7']"

  strings:
    $hex_string = { a1 02 4d 6d 47 65 74 53 79 73 74 65 6d 52 6f 75 74 69 6e 65 41 64 64 72 65 73 73 00 1d 04 52 74 6c 49 6e 69 74 55 6e 69 63 6f 64 65 53 74 72 69 6e 67 00 00 7d 03 50 73 4c 6f 6f 6b 75 70 50 72 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}