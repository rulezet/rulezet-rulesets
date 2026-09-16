rule o3e9_31329104ea211912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.31329104ea211912"
    cluster      = "o3e9.31329104ea211912"
    cluster_size = "8663"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vbkrypt eyestye injector"
    md5_hashes   = "['0006be9fca9df211f9db10c2d1fa034c','0007d2fdc36139d12cac9ac44e44fd1f','01188cf7f6b8d254f3f48b79014e02de']"

  strings:
    $hex_string = { d9 00 00 00 d5 00 00 00 d2 00 00 00 cd 00 00 00 c9 00 00 00 c4 00 00 00 bf 00 00 00 ba 00 00 00 b4 00 00 00 ae 00 00 00 a8 00 00 00 a1 00 00 00 9a 00 00 00 93 00 00 00 8b 00 00 00 83 00 00 00 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}