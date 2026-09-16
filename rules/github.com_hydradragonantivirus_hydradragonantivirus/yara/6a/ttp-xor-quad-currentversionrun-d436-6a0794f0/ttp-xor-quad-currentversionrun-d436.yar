rule TTP_XOR_QUAD_CurrentVersionRun_d436 {
  strings:
    $key_d436 = { 87 59 [2] a3 57 [2] 88 7b [2] a6 59 [2] b2 42 [2] bd 58 [2] a3 45 [2] a1 44 [2] ba 42 [2] a6 45 [2] ba 6a }

  condition:
    any of them
}