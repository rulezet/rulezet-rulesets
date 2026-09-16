rule _20160921_2eacd3ef1ce6866325342ce8cba80e38_20160921_cebdb99ce2e5_2842 {
  meta:
    description = "datamaliciousorder - from files 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash2       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"

  strings:
    $s1 = "Bb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s2 = "n f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s3 = "){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";}" ascii
    $s4 = ",(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){" ascii
    $s5 = " f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MD" ascii
    $s6 = " \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(func" ascii
    $s7 = "0(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Nx\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}