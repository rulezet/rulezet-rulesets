rule p3e9_1198bb49c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3e9.1198bb49c8000b12"
    cluster      = "p3e9.1198bb49c8000b12"
    cluster_size = "82"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock pxbii nabucur"
    md5_hashes   = "['0b80d08a18b5b85d721ea7f2ef13dd75','0b9f54d048a283684a986e1b83337286','a55de21276de09b7f1682721586925cd']"

  strings:
    $hex_string = { f3 cd ab ff f0 ca a9 ff ed c7 a8 ff e9 c3 a5 ff e6 c0 a3 ff e2 bc a1 ff de b8 9f ff da b4 9e ff d6 b1 9b ff d3 ad 99 ff cf aa 97 ff cc a6 96 ff c9 a4 94 ff b1 7f 73 ff 03 03 03 23 0b 0b 0b 0b }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}