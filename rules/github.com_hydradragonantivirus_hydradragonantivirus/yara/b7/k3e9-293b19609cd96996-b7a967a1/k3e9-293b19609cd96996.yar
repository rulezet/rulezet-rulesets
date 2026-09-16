rule k3e9_293b19609cd96996 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.293b19609cd96996"
    cluster      = "k3e9.293b19609cd96996"
    cluster_size = "359"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installcore unwanted click"
    md5_hashes   = "['001f4bf466174b7ea3fbba9a35eea9cd','02ab7f42a98916ebce37c25c5991f3d6','0e57b53680dfa85104d92189112b0bea']"

  strings:
    $hex_string = { 16 74 db be 47 48 98 bf de 99 02 49 20 2f df 65 7d 9e 2a 75 ea f1 b1 5d b7 1d 5b 0d 6d c2 73 a3 38 3e 36 37 76 45 70 f8 c4 da 2d f9 4d a1 d9 13 cf 6b 10 30 fb e9 54 a2 28 60 69 66 06 ae 62 77 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}