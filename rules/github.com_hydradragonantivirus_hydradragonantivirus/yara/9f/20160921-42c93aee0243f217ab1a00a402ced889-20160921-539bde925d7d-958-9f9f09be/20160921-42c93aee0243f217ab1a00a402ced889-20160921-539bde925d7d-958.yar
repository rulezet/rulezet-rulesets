rule _20160921_42c93aee0243f217ab1a00a402ced889_20160921_539bde925d7d_958 {
  meta:
    description = "datamaliciousorder - from files 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash2       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash3       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1  = "on f000(){return \"Br\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"" ascii
    $s2  = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"BMj\";})(),(function f000()" ascii
    $s3  = "n \"PTi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s4  = "urn \"Br\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Nv\";})(),(fu" ascii
    $s5  = "n \"Tn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s6  = "nction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){retur" ascii
    $s7  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s8  = "ion f000(){return \"MOc\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DAp\";})(),(function f000(){return " ascii
    $s9  = "00(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\"" ascii
    $s10 = "ction f000(){return \"XTn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s11 = "000(){return \"MBb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s12 = "0(){return \"Vj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s13 = "function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DYs\";})(),(function f000(){r" ascii
    $s14 = "\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s15 = "unction f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s16 = "00(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Br\";" ascii
    $s17 = "tion f000(){return \"Yv\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s18 = "n f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s19 = "(){return \"Sj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s20 = "tion f000(){return \"ZIi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}