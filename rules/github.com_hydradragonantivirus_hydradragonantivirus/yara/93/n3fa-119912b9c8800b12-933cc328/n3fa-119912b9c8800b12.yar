rule n3fa_119912b9c8800b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3fa.119912b9c8800b12"
    cluster      = "n3fa.119912b9c8800b12"
    cluster_size = "286"
    filetype     = "PE32+ executable (DLL) (GUI) x86-64"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dangerousobject fari kryptik"
    md5_hashes   = "['01483875dd2b0c8c2c9ada9ad62540ed','01ab22243c98a71da517ce5842479d20','0e9674eb1a81c2d242d52a7d3cf8161d']"

  strings:
    $hex_string = { be db eb e0 f6 5c 44 86 c0 58 6c a0 d9 b3 05 0e bf 2b 60 de 23 3a cb 9a d6 50 91 bc 17 e8 dd d4 57 27 79 41 38 5b b4 72 bd 0c 1b e6 9b 4c 51 9c 2d 6d 5f 4e 0f 37 7f 3c 1c 12 2a 08 a5 63 1f d3 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}