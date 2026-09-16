rule j2319_4a249a912d2d48ba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2319.4a249a912d2d48ba"
    cluster      = "j2319.4a249a912d2d48ba"
    cluster_size = "7"
    filetype     = "HTML document"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cryxos html expkit"
    md5_hashes   = "['12114a6fd3ad24a225a29eab244a38e0','2347dd1b2eb49f7d1122cf52f243e96e','ffcd402900a351cb8ab14ff28f271c1e']"

  strings:
    $hex_string = "ext/javascript\">\r\n<!--\r\ndocument.write(unescape('%3c%64%69%76%20"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}