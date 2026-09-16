rule o3e9_39b1144f97a30b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.39b1144f97a30b12"
    cluster      = "o3e9.39b1144f97a30b12"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonstr malicious badfile"
    md5_hashes   = "['486b5edd60998b949e4dae92e66cb988','5778e0b60870e9635f3734e24a81aad4','de3d37a471bfedcc7af75ef36eaf7697']"

  strings:
    $hex_string = { bb 78 83 fa 9d 0a 91 cb f2 12 f6 44 e8 d9 72 21 0f 65 49 31 dc e2 cc c7 b3 74 92 dd af 77 f5 34 28 07 a4 e3 fb 84 b6 26 7b 20 b0 ae 36 37 15 7e e1 75 08 2e 05 38 62 f3 b8 5f b1 e6 a1 e0 5b 79 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}