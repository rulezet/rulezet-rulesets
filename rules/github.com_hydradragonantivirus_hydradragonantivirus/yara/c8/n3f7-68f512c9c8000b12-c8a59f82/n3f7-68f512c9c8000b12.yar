rule n3f7_68f512c9c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.68f512c9c8000b12"
    cluster      = "n3f7.68f512c9c8000b12"
    cluster_size = "524"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit html script"
    md5_hashes   = "['01cde3b6e4515941873cc4ad0b9bceda','038e0e2e721fb77ca25e89714c78bf1f','10e882c78601aaf7a4431456588d9313']"

  strings:
    $hex_string = "te Chr(CLng(\"&H\" & Mid(WriteData,i,2)))\r\nNext\r\nFileObj.Close\r\nEn"

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}