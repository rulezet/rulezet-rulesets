rule n3fd_0842892c5ba30914 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3fd.0842892c5ba30914"
    cluster      = "n3fd.0842892c5ba30914"
    cluster_size = "950"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "browsefox yontoo advml"
    md5_hashes   = "['00043c33a7a31d2449c1a9ff9fa07817','0066d9bdd1495650b1d1e41573720957','045fb0132d53c715356ad499182341b6']"

  strings:
    $hex_string = { 84 cd 1c 0a 20 01 01 15 12 80 ad 01 13 00 09 00 00 15 12 80 95 01 13 00 06 15 12 80 95 01 0e 07 20 02 0e 0e 12 81 e5 08 07 02 12 81 dd 11 85 05 05 20 00 11 85 05 0c 07 04 12 82 79 12 82 c4 08 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}