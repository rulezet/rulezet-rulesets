rule _20160921_3e5e21af311d364f73107419b54e74e3_20160921_9388afe79f2f_1847 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash2       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash3       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"
    hash4       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"

  strings:
    $s1  = "nction f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s2  = "eturn \"TKp\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})()" ascii
    $s3  = "ion f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return" ascii
    $s4  = "return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(" ascii
    $s5  = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Tb\";})(),(funct" ascii
    $s6  = ";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f0" ascii
    $s7  = "0(){return \"KDh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s8  = "on f000(){return \"Nv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s9  = "(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s10 = "function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}