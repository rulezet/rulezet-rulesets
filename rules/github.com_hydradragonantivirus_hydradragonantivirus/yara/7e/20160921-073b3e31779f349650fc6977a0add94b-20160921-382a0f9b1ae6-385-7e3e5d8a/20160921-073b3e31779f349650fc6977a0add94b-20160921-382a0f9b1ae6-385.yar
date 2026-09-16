rule _20160921_073b3e31779f349650fc6977a0add94b_20160921_382a0f9b1ae6_385 {
  meta:
    description = "datamaliciousorder - from files 20160921_073b3e31779f349650fc6977a0add94b.js, 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d01505d8ea4f2da2961c36fda33950e39ba720d54d967d434c0c5003ff7d2f"
    hash2       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash3       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"

  strings:
    $s1  = "{return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wb\";})" ascii
    $s2  = "nction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){ret" ascii
    $s3  = "0(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Lp\";" ascii
    $s4  = "00(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZGq\"" ascii
    $s5  = "ion f000(){return \"MMz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s6  = "t\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s7  = "on f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"D" ascii
    $s8  = "f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq" ascii
    $s9  = "000(){return \"HJm\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s10 = "0(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Oe\";" ascii
    $s11 = " \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s12 = "{return \"ZGq\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";}" ascii
    $s13 = "Gq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(functi" ascii
    $s14 = "n\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s15 = "eturn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(" ascii
    $s16 = "f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj" ascii
    $s17 = "return \"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(" ascii
    $s18 = "\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function " ascii
    $s19 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTi\";" ascii
    $s20 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}