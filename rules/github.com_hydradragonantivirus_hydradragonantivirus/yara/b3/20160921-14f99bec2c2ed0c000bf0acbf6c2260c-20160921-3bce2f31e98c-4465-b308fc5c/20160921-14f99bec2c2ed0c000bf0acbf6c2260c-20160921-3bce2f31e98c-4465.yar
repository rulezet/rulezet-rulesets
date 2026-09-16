rule _20160921_14f99bec2c2ed0c000bf0acbf6c2260c_20160921_3bce2f31e98c_4465 {
  meta:
    description = "datamaliciousorder - from files 20160921_14f99bec2c2ed0c000bf0acbf6c2260c.js, 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_b5e2b5a2e8f104e719b3c6631c08f1f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224106b166fc0a998ec1d58e5d4a78c585bdeb76194d93210753d7d0f558c06b"
    hash2       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash3       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash4       = "8495e7e7fc77026b5e5681ac973eefb0561cb5cce78632996de59641ce00258e"

  strings:
    $s1 = "rn \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(fu" ascii
    $s2 = "ion f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s3 = "Ia\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(functio" ascii
    $s4 = "000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\"" ascii
    $s5 = "{return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}