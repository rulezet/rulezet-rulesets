rule _20160921_a3256642bcc1ce0dfec8677fe62bc590_20160921_b2002e7f99c6_3104 {
  meta:
    description = "datamaliciousorder - from files 20160921_a3256642bcc1ce0dfec8677fe62bc590.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"
    hash2       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"

  strings:
    $s1 = "\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function " ascii
    $s2 = "WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s3 = "GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(functio" ascii
    $s4 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"PTi\";})(),(function f0" ascii
    $s5 = "turn \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(" ascii
    $s6 = "eturn \"XTn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()," ascii
    $s7 = " f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}