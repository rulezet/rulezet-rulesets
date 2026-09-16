rule n3f7_4b14208bc2220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.4b14208bc2220b12"
    cluster      = "n3f7.4b14208bc2220b12"
    cluster_size = "10"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "clicker faceliker script"
    md5_hashes   = "['02f63e8cf0a9322afe8533190aa2c280','1728e1f63b222fc6caff240e2f112ae6','ef9a832f1c7160d6f0acc56be3baf2b7']"

  strings:
    $hex_string = ".getElementById('PopularPosts1'), {}, 'displayModeFull'));\n_Widg"

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}