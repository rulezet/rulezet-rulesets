rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_5f5611940db7_1653 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"

  strings:
    $s1  = "return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Iq\";})()" ascii
    $s2  = "n f000(){return \"MBb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s3  = "o\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s4  = "Gn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s5  = "return \"SEo\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(" ascii
    $s6  = "ion f000(){return \"TKp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s7  = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Vj" ascii
    $s8  = "(function f000(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){r" ascii
    $s9  = "0(){return \"EZu\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\"" ascii
    $s10 = "on f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return " ascii
    $s11 = "})(),(function f000(){return \"Br\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Br\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}