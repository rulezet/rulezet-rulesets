rule o3e9_16512c4ad6d24b9a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.16512c4ad6d24b9a"
    cluster      = "o3e9.16512c4ad6d24b9a"
    cluster_size = "579"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['000aeb0c4fd63ef33281d7c7429c49fc','008727b36a13b4138a874c4abd8ed05e','09a81965bd90de7936f2d2134bb47070']"

  strings:
    $hex_string = { 10 ba 41 97 f1 6e 82 33 06 2d b0 43 45 a5 0f f8 b2 8a b9 6d cf be b9 a4 d9 07 0d 96 a3 ab d5 0f e7 f8 a4 c6 8f 07 ce 1d 25 ba cc 20 ed 04 2e 25 2a aa 9c 89 79 69 1f 8e b7 bb 1e fe 62 c6 65 b6 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}