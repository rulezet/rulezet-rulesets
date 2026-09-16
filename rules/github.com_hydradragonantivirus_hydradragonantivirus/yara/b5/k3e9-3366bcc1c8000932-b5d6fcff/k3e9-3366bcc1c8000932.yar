rule k3e9_3366bcc1c8000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.3366bcc1c8000932"
    cluster      = "k3e9.3366bcc1c8000932"
    cluster_size = "2283"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "bublik generickd upatre"
    md5_hashes   = "['00485919a3abadf7db28c460a5c62205','00bc02e40b80429bb46d3185b08e6206','0332baef0f78fdd9577548b2467d8de5']"

  strings:
    $hex_string = { 5e d2 af 8a a0 e9 34 2f 07 0a 04 b5 6e 56 ce b7 f1 c8 a0 07 0a 04 46 ba 5c 7d 86 17 a8 2a 02 0a 04 48 7e b4 a5 cb dc ea c3 08 0a 04 e8 96 5d f4 e0 63 24 77 01 0a 04 80 96 76 a9 42 8e 9a 9b 0d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}