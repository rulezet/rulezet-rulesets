rule _20160921_6748b4ad3c83a7c4aeacfc0817a81797_20160921_b71168af39c5_5334 {
  meta:
    description = "datamaliciousorder - from files 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js, 20160921_b71168af39c5eec1d403d381eea7ffe1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"
    hash2       = "c8811edeb74999e8dd226f7fa9d7963ccfc998904ecb9474d036376253dc6fde"

  strings:
    $s1 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retur" ascii
    $s2 = "function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){ret" ascii
    $s3 = "){return \"Go\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s4 = "000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx" ascii
    $s5 = "n \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}