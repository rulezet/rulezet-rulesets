rule k3e9_0cb94a52dc62f112 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0cb94a52dc62f112"
    cluster      = "k3e9.0cb94a52dc62f112"
    cluster_size = "22530"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "unruy cosmu cycler"
    md5_hashes   = "['0000ccdd4db5339c9ea00dbf30903e63','000349ce6bf22d1f3ab9894e03c1755c','0068eb20f59b65afd91fdc51418c62ee']"

  strings:
    $hex_string = { 59 e4 5d 92 46 a3 d5 4f d9 c5 15 a4 6b 51 dd af 48 fb 58 10 ee f2 fe bc 4b f7 9d 73 60 3e e5 a0 cc a1 76 a6 f8 91 8c f5 9b 37 29 b5 2e 77 57 bd df 74 ac 8a 0d 1d 56 de 5c 95 00 ec 69 45 c8 ed }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}