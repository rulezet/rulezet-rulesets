rule o3f1_516bbac1c8000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f1.516bbac1c8000932"
    cluster      = "o3f1.516bbac1c8000932"
    cluster_size = "261"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hiddad androidos mobidash"
    md5_hashes   = "['022dfc3069b91e62e3ee4b5ad3046078','024fc6b84f9748a8828079fcb89d8f8b','13073319b1d571e8fe640d9d6bb42154']"

  strings:
    $hex_string = { c7 02 01 01 08 00 00 01 49 00 02 7f 10 00 03 00 de 02 00 00 0c 00 03 01 21 00 00 00 30 00 01 01 08 00 00 01 26 00 0b 7f 31 00 01 01 08 00 00 01 0a 00 0b 7f 32 00 01 01 08 00 00 04 9a 99 19 3f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}