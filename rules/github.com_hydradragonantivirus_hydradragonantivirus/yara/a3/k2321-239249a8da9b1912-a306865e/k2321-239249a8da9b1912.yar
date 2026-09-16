rule k2321_239249a8da9b1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.239249a8da9b1912"
    cluster      = "k2321.239249a8da9b1912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "symmi swisyn abzf"
    md5_hashes   = "['26efccd883003894d38dc3ba8fd562f7','34bea391d90c4bdc719205c0f749ad9d','c6f8a16bcf8385622f75696072627d6e']"

  strings:
    $hex_string = { 70 8e 0d 02 c6 96 97 e7 4b f8 e4 49 ae 28 e0 bf b9 b3 ac 82 31 b4 30 5d e8 bb e6 39 66 d6 9f 3b 3f ca 53 7c f7 ad c2 ce 2c 6c 7d d2 d7 c5 9a a4 ba 18 42 13 56 5e 17 37 51 6c 15 8d 43 8a ef 83 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}