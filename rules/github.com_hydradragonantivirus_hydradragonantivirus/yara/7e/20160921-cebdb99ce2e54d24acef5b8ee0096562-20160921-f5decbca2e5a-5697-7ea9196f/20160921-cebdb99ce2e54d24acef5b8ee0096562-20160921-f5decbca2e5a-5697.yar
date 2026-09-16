rule _20160921_cebdb99ce2e54d24acef5b8ee0096562_20160921_f5decbca2e5a_5697 {
  meta:
    description = "datamaliciousorder - from files 20160921_cebdb99ce2e54d24acef5b8ee0096562.js, 20160921_f5decbca2e5a35bbb5c42091c1b0c30e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"
    hash2       = "5fe03908bd7d860f1260a3264b2e10de3115d24242a095cf4c0b73e7934ce89e"

  strings:
    $s1 = "f000(){return \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"G" ascii
    $s2 = "n f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"" ascii
    $s3 = "turn \"Mc\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s4 = "(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(" ascii
    $s5 = "})(),(function f000(){return \"Um\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"RVb\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}