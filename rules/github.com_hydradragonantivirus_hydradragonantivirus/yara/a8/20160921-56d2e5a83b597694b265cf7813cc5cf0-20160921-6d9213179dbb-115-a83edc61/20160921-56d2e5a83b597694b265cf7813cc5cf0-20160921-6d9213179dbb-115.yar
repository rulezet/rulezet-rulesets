rule _20160921_56d2e5a83b597694b265cf7813cc5cf0_20160921_6d9213179dbb_115 {
  meta:
    description = "datamaliciousorder - from files 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_6d9213179dbb863530a638df47003a46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash2       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"

  strings:
    $s1  = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return " ascii
    $s2  = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wb\";})()," ascii
    $s3  = "{return \"Ot\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"KDh\";})" ascii
    $s4  = "{return \"TKp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii
    $s5  = "(function f000(){return \"NYh\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s6  = "(),(function f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s7  = "})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(function f000" ascii
    $s8  = "turn \"MDb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})()," ascii
    $s9  = "n \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s10 = "\"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(funct" ascii
    $s11 = "0(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\"" ascii
    $s12 = "on f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s13 = "b\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s14 = "tion f000(){return \"QDg\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"EZu\";})(),(function f000(){retur" ascii
    $s15 = "function f000(){return \"Sq\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s16 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Wb\";})(),(function f000(){retu" ascii
    $s17 = "nction f000(){return \"KDh\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii
    $s18 = "ion f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return" ascii
    $s19 = "function f000(){return \"Tb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Km\";})(),(function f000(){ret" ascii
    $s20 = "00(){return \"Sj\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}