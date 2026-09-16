rule j3ec_45b46c9c96bf6932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ec.45b46c9c96bf6932"
    cluster      = "j3ec.45b46c9c96bf6932"
    cluster_size = "424"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fileinfector aydm malicious"
    md5_hashes   = "['00505eaa0282caff667143e0226a701f','00818fdfc7cce56a998a83f6ec53ef86','0ac12562ab1500d1d9ef68aae92bb28f']"

  strings:
    $hex_string = { ff bb 06 00 00 00 31 d2 f7 f3 83 fa 04 77 20 8d b5 fc fd ff ff 31 c0 ac 85 d2 74 05 01 c6 4a eb f6 89 f3 5e 87 f3 5f 89 c1 f3 a4 87 f3 eb 02 5e 5f 59 49 85 c9 74 02 eb 83 8b 45 50 29 c7 c3 8d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}