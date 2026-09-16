rule j2377_6136ea49c0001932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2377.6136ea49c0001932"
    cluster      = "j2377.6136ea49c0001932"
    cluster_size = "5"
    filetype     = "HTML document"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171121"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "iframe html iframeref"
    md5_hashes   = "['124a7bd26ea5122244f53cc5843b86ad','2724831172eb6a74af9351036c93f73c','8c109990896483576b793d7bd7ee70a8']"

  strings:
    $hex_string = "24 width=89 src=http://nmsbaseball.com/post.php?id=281559></ifra"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}