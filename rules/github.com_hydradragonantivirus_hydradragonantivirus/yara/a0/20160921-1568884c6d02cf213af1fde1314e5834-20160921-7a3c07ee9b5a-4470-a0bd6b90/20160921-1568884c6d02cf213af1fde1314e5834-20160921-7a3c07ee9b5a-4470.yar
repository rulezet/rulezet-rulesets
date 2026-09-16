rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_7a3c07ee9b5a_4470 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"

  strings:
    $s1 = "function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){r" ascii
    $s2 = "),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000()" ascii
    $s3 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";" ascii
    $s4 = "eturn \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})()," ascii
    $s5 = " f000(){return \"PTs\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"G" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}