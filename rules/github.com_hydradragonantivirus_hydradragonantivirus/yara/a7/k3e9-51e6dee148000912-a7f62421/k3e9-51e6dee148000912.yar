rule k3e9_51e6dee148000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.51e6dee148000912"
    cluster      = "k3e9.51e6dee148000912"
    cluster_size = "15004"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "razy upatre malicious"
    md5_hashes   = "['00018e44225da115e3cb10917cb18238','0006c07d7cf8fe814f8b3a88b6d1fb8c','00a5fdf670f60162f41cc920a1d000c0']"

  strings:
    $hex_string = { 68 7c 21 00 02 24 41 0f 8d 52 f7 15 3e 1c f8 ff 55 0f 01 75 c0 e9 87 fa ff fb 83 4d f0 85 8b 90 c0 8b 41 38 fd 75 f8 03 bf 84 0f 83 04 0b b7 44 06 6b c1 28 8b 24 8d 8b 8b 84 f9 cb fe fc ff 8a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}