rule _20160921_7a3c07ee9b5aeabadf2f6cce951819f0_20160921_a3256642bcc1_5430 {
  meta:
    description = "datamaliciousorder - from files 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash2       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"

  strings:
    $s1 = "0(){return \"Um\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";}" ascii
    $s2 = "turn \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s3 = "),(function f000(){return \"Lp\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(){" ascii
    $s4 = ";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f00" ascii
    $s5 = "function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}