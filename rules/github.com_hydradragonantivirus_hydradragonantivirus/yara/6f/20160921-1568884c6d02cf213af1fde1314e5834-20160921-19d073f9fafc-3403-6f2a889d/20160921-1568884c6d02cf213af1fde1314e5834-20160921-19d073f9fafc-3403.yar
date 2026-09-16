rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_19d073f9fafc_3403 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_19d073f9fafc88c8b86047e72c80e9d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"

  strings:
    $s1 = "f000(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa" ascii
    $s2 = "ion f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return " ascii
    $s3 = "ction f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s4 = "f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"MMz" ascii
    $s5 = "Kl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function" ascii
    $s6 = "urn \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Wy\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}