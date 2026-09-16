rule _20160921_619a314e9bcca286c046dff250b54b6b_20160921_d1c97b87a698_3846 {
  meta:
    description = "datamaliciousorder - from files 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "\"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(funct" ascii
    $s2 = "unction f000(){return \"RLk\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s3 = "eturn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Uo\";})()," ascii
    $s4 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Rh\";})(),(funct" ascii
    $s5 = "n f000(){return \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"" ascii
    $s6 = ",(function f000(){return \"Uo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}