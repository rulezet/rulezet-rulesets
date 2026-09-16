rule n3ed_114331e9ca000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3ed.114331e9ca000912"
    cluster      = "n3ed.114331e9ca000912"
    cluster_size = "5"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "symmi banhguo lmir"
    md5_hashes   = "['3b70431b52e11144b2d372b1508f01cf','5ccbef30a204c7fc80f487b3a894fbe6','da99af2dfe288e5cfdd78a6b75244652']"

  strings:
    $hex_string = { 36 a5 2b d9 eb 53 80 74 63 7f c9 e4 52 a9 1b f1 0c 3a 62 e0 e5 3c 39 90 32 37 e3 34 33 69 c5 86 69 c2 35 87 e2 21 75 a1 a0 6e 14 40 17 a3 8c 0a f2 5b df 83 47 bc 23 fe ec 64 55 8b ac 24 84 91 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}