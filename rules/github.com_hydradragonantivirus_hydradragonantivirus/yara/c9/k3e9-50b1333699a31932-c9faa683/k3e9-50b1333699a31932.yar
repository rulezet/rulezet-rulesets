rule k3e9_50b1333699a31932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.50b1333699a31932"
    cluster      = "k3e9.50b1333699a31932"
    cluster_size = "27"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['041656175ae069c571307da9ba410e61','0ab6b5f5409233bc8dac72e8b7ce0be6','bfd04777f5e652c70172d01729030fbb']"

  strings:
    $hex_string = { 00 01 78 13 00 01 64 13 00 01 4c 13 00 01 34 13 00 01 1c 13 00 01 04 13 00 01 ec 12 00 01 cc 12 00 01 b4 12 00 01 8c 12 00 01 70 12 00 01 50 12 00 01 28 12 00 01 08 12 00 01 bf 44 ff ff 40 bb }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}