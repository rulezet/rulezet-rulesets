rule EC_curve__EC_NIST_CHAR2_163B_SEED__8_byt_20_ {
  strings:
    $a0 = { 85 e2 5b fe 5c 86 22 6c db 12 01 6f 75 53 f9 d0 e6 93 a2 68 }

  condition:
    $a0
}