rule k3e9_1395b6b9ce400916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1395b6b9ce400916"
    cluster      = "k3e9.1395b6b9ce400916"
    cluster_size = "127"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ipamor azbaukwkdpb backdoor"
    md5_hashes   = "['028095a03ec544bd4bcf60c496911624','0977f40e96fe631e183972588ca55be3','33eb75abde2309da7c61688395816ba5']"

  strings:
    $hex_string = { c8 5b 5e 5f 5d c3 31 c0 b2 01 f0 0f b0 53 20 0f 94 c2 84 d2 74 9d 8b 73 1c 8b 43 14 39 c6 72 07 31 c0 86 43 20 eb 8c 8b 43 14 89 c7 51 c1 e0 02 68 40 d9 06 00 50 29 f7 8b 53 24 52 e8 f2 ea fb }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}