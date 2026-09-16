rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_24cca85b9483_4505 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash3       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"

  strings:
    $s1 = "00(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\"" ascii
    $s2 = " \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(fun" ascii
    $s3 = "f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp" ascii
    $s4 = "urn \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(f" ascii
    $s5 = "(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}