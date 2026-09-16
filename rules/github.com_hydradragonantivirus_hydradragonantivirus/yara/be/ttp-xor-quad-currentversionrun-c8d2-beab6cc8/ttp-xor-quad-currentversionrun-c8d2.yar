rule TTP_XOR_QUAD_CurrentVersionRun_c8d2 {
  strings:
    $key_c8d2 = { 9b bd [2] bf b3 [2] 94 9f [2] ba bd [2] ae a6 [2] a1 bc [2] bf a1 [2] bd a0 [2] a6 a6 [2] ba a1 [2] a6 8e }

  condition:
    any of them
}