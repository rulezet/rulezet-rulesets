rule k2321_09b26112d9db4912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09b26112d9db4912"
    cluster      = "k2321.09b26112d9db4912"
    cluster_size = "8"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nimnul vjadtre small"
    md5_hashes   = "['52503f0646cf84b06378806779f5db7f','7da4e9e23a8463a28d1592d3d8be5627','fb6b6f15ef86dee28cbe3972f398df4f']"

  strings:
    $hex_string = { 35 da 6d 25 19 d9 d8 7c 5f 62 aa 84 ba 02 8d 94 cb bf 2d 52 b6 04 03 ea 17 68 b5 72 00 fa a9 94 fe a3 e8 5b 92 89 c5 6a 46 c1 2e f0 d2 b7 06 93 a5 38 1b 56 29 26 72 f4 fb bc 44 0e 5d 3e e9 f1 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}