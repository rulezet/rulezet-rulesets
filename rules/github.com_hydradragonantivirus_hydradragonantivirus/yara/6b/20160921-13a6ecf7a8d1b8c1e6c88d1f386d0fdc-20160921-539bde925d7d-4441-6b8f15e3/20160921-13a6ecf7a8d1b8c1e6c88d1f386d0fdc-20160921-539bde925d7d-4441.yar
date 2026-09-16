rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_539bde925d7d_4441 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash3       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1 = "00(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"RVb" ascii
    $s2 = " \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qa\";})(),(fun" ascii
    $s3 = "rn \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx\";})(),(" ascii
    $s4 = "rn \"PTs\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s5 = "function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"PTs\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}