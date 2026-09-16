rule _20160921_74aa1eb054c4d9cf85bcad2468e8404a_20160921_8aaa596582e2_3046 {
  meta:
    description = "datamaliciousorder - from files 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js, 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"
    hash2       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash3       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash4       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){ret" ascii
    $s2 = "function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){re" ascii
    $s3 = "on f000(){return \"WIj\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s4 = "return \"PTi\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})()" ascii
    $s5 = "n \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(fun" ascii
    $s6 = "(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";" ascii
    $s7 = "00(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}