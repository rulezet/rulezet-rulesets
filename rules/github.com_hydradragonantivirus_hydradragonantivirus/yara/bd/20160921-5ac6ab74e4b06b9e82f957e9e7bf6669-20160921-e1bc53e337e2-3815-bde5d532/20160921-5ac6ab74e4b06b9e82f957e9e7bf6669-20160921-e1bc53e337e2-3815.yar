rule _20160921_5ac6ab74e4b06b9e82f957e9e7bf6669_20160921_e1bc53e337e2_3815 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"
    hash2       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"

  strings:
    $s1 = "f000(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MM" ascii
    $s2 = "function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){re" ascii
    $s3 = "00(){return \"TRc\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo" ascii
    $s4 = "on f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s5 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return" ascii
    $s6 = "n f000(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}