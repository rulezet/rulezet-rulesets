rule k2321_13959250c902f916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.13959250c902f916"
    cluster      = "k2321.13959250c902f916"
    cluster_size = "3"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "regrun ludbaruma rontokbro"
    md5_hashes   = "['54c28d5b105a544bfeb2446369c6cd1b','7e4a205f8f7ccef964dcaadc2161ca36','987ae409b1869c55a0d326314f24380e']"

  strings:
    $hex_string = { 43 9e 1a a5 7f 6a 12 63 c3 31 7e 99 e8 67 8a 69 f4 fa 29 71 ea b3 e2 d4 e7 41 58 9f a6 f7 22 d9 a9 24 a1 53 11 48 60 fc 3f 66 47 ca ad 28 bf 92 ae 96 e7 ec 44 39 45 2d bf b7 37 81 d5 8d 51 cb }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}