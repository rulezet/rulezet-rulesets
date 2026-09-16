rule _20160921_8aaa596582e26eec62319f01660d922b_20160921_f1aea308b200_5503 {
  meta:
    description = "datamaliciousorder - from files 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash2       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"
    hash3       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = " f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"" ascii
    $s2 = " f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Q" ascii
    $s3 = "turn \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Mt\";})(),(" ascii
    $s4 = "n \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"BQb\";})(),(fu" ascii
    $s5 = "(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}