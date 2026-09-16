rule TTP_XOR_QUAD_CurrentVersionRun_d446 {
  strings:
    $key_d446 = { 87 29 [2] a3 27 [2] 88 0b [2] a6 29 [2] b2 32 [2] bd 28 [2] a3 35 [2] a1 34 [2] ba 32 [2] a6 35 [2] ba 1a }

  condition:
    any of them
}