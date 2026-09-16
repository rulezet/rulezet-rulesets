rule _20160921_382a0f9b1ae693f8ade627fd2d6a8b52_20160921_54325d6949c5_1703 {
  meta:
    description = "datamaliciousorder - from files 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash2       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash3       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"

  strings:
    $s1  = "00(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\"" ascii
    $s2  = "\"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Iq\";})(),(funct" ascii
    $s3  = " \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"PTs\";})(),(fun" ascii
    $s4  = "){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";}" ascii
    $s5  = ",(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"RPt\";})(),(function f000(){" ascii
    $s6  = " \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(func" ascii
    $s7  = "on f000(){return \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s8  = " \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(fun" ascii
    $s9  = "ion f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s10 = "{return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(" ascii
    $s11 = "00(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}