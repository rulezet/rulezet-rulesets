rule k3e9_13934c99cfbb0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.13934c99cfbb0912"
    cluster      = "k3e9.13934c99cfbb0912"
    cluster_size = "12"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androm backdoor symmi"
    md5_hashes   = "['2253b6edd276785887b9180e6a8c9185','29fbd05f3f650e79a48e445aed5df3d0','c5cd1835297fd924f888599012c96013']"

  strings:
    $hex_string = { 4e 60 bb 5b df ad 7a a8 3c 46 c8 fe b2 84 26 be 10 a7 1c b4 e3 1d 3a e0 75 bd ca b0 06 20 ef 9d dc e3 18 fa b1 fd e9 0a d8 1f 5d a1 dd 14 36 9f 73 38 b5 f9 29 62 67 b9 0f 96 5c 3e 49 2e da 78 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}