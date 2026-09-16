rule _20160921_aed247f3d2282ef44bd04021d1a47ef8_20160921_b132808f30a4_939 {
  meta:
    description = "datamaliciousorder - from files 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b132808f30a4f3b5c484e9734dc93fcc.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js, 20160921_e1c974d7750547ace34afdda5a06de15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash2       = "03f070dd06dae48f7c253ddc9a238e441aaac22f9de6e238ba5d3ffa0b9220b4"
    hash3       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"
    hash4       = "bed4e8c71e09f1ca8c800564bc43d4e103353ec558d1f0869c85d3e8f8c43b01"

  strings:
    $s1  = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return" ascii
    $s2  = "return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"IPu\";})(" ascii
    $s3  = "0(){return \"RLk\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"XTn\"" ascii
    $s4  = "n\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function" ascii
    $s5  = "eturn \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(" ascii
    $s6  = "0(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";" ascii
    $s7  = "000(){return \"Tn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s8  = "tion f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s9  = "0(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Oe\";}" ascii
    $s10 = "(),(function f000(){return \"Rh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s11 = "b\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s12 = "(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){re" ascii
    $s13 = "function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){r" ascii
    $s14 = "n f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s15 = "DYs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s16 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sv\";}" ascii
    $s17 = " f000(){return \"PTi\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"" ascii
    $s18 = "{return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s19 = "ction f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\";})(),(function f000(){retur" ascii
    $s20 = " \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Wy\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}