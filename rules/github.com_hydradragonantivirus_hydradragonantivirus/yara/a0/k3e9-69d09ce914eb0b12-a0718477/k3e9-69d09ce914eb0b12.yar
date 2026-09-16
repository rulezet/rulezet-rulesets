rule k3e9_69d09ce914eb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.69d09ce914eb0b12"
    cluster      = "k3e9.69d09ce914eb0b12"
    cluster_size = "457"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mywebsearch mindspark riskware"
    md5_hashes   = "['007fd6d1702527d2b126f7d4203f8e13','00b9a720a51406e0e8c18c40bb1d6abc','093294a76ba0a05fcc4350b4a68e57d5']"

  strings:
    $hex_string = { e2 88 fd ae 3c c4 94 e4 f2 24 1d 6e 38 27 e1 45 66 33 73 f1 79 50 2e 4f c1 89 51 32 ba fc 46 4d 4a 61 3d 7f 87 f0 5b f9 fa d9 c5 f6 76 a3 73 65 53 a9 8e dc 1e 26 67 41 b8 92 8d f7 04 d4 3b 2d }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}