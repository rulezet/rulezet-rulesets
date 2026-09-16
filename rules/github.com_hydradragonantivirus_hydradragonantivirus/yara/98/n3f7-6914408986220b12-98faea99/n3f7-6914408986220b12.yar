rule n3f7_6914408986220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.6914408986220b12"
    cluster      = "n3f7.6914408986220b12"
    cluster_size = "112"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "clicker faceliker html"
    md5_hashes   = "['02ccab686e8ef4c9c315958f394e0fe0','05313c21e99980775433080cb68a7f2c','23e1c80410c3b4d4382138718e39e5b6']"

  strings:
    $hex_string = "r.com/rearrange?blogID=8966490275696443711&widgetType=BlogArchiv"

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}