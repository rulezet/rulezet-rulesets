rule k3e9_431ace0e92bb9b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.431ace0e92bb9b12"
    cluster      = "k3e9.431ace0e92bb9b12"
    cluster_size = "105"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rimod emailworm fakefolder"
    md5_hashes   = "['00191c5d13f66649b9a92927b7d65828','01273d4aec5c39cb4269d4c544b86fda','2f8eab585deb803acc097fc902f23abd']"

  strings:
    $hex_string = { 9a c6 00 18 96 c0 00 1b 9c c7 00 18 79 9c 00 19 7a 9d 00 21 a2 ce 00 25 a2 cf 00 28 99 bf 00 6b d7 ff 00 42 b3 e2 00 42 b2 de 00 52 be e7 00 6f d5 fd 00 42 ba ef 00 0c 72 a5 00 5a c7 ff 00 84 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}