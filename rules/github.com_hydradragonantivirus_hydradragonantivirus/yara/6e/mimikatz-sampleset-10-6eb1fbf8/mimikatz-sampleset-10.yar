rule Mimikatz_SampleSet_10: APT {
  meta:
    description = "Mimikatz Rule generated from a big Mimikatz sample set"
    author      = "Florian Roth - Florian Roth"
    super_rule  = 1
    hash0       = "5522fd8fe2e205b30f9e74a94da0352d"
    hash1       = "ec428ed7d1cc4ba3023696ddc138a376"
    hash2       = "13e88493f844a0df3352cd721bfa41a6"
    hash3       = "483e5365e1f1d83c2dcd4bdb398e779f"
    hash4       = "04d04a1f0ff9e2ff1d35b8c2950cce53"
    hash5       = "97cbbd6c4153ae4a410439e2c02d77ce"
    hash6       = "b43dfc8be8db7eacfc993e323229fb9f"
    hash7       = "72e95180a2e4ab59e1b7c10f1054740a"
    hash8       = "eaaecd5bd100923c72d2b39d84dfd411"
    hash9       = "a8ae792f0384fd3e7f411c826b48b7c8"
    score       = 40

  strings:
    $s0 = "D$hL9(t" fullword
    $s1 = "l$LfD9o" fullword
    $s2 = "AHH90t?L" fullword
    $s3 = "M9Qpv\"I9Ips" fullword
    $s4 = "tSD8T$<u" fullword
    $s5 = ";f9T$Xw" fullword
    $s6 = "6f9L$Xw" fullword
    $s7 = "f;\\$@u1E3" fullword
    $s8 = "8\\$8uFH" fullword
    $s9 = "L$DfD;O" fullword

  condition:
    all of them
}