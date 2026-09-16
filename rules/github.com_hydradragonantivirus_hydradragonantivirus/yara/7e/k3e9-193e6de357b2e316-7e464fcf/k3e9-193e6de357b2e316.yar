rule k3e9_193e6de357b2e316 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.193e6de357b2e316"
    cluster      = "k3e9.193e6de357b2e316"
    cluster_size = "29"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installcore unwanted malicious"
    md5_hashes   = "['10ecfdd92c7bc227e2de71dcf9df060e','14a2e30ee1fcf3df185c13e5ef019224','8cc047264373769ea196af1e20ac64c6']"

  strings:
    $hex_string = { 04 c0 f1 01 cd 4c d0 ec 15 f8 64 f0 58 3d a8 4e ca c4 8f 53 e5 de 0d 05 4a 7e 3f f9 21 b1 79 41 bf dd 02 ea f4 a3 27 93 26 92 a5 ad 5e d3 88 43 36 af f7 1c 03 ff a0 e9 74 2f e0 5f e6 7b 34 57 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}