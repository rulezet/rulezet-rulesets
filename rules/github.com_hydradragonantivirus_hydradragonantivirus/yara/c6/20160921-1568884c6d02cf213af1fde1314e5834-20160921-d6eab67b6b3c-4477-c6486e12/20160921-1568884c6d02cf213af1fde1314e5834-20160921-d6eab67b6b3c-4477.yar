rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_d6eab67b6b3c_4477 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"

  strings:
    $s1 = "){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})" ascii
    $s2 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f00" ascii
    $s3 = "n \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s4 = "unction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){ret" ascii
    $s5 = "\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}