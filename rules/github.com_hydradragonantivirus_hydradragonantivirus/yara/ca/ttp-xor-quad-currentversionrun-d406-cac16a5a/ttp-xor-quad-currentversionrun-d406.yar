rule TTP_XOR_QUAD_CurrentVersionRun_d406 {
  strings:
    $key_d406 = { 87 69 [2] a3 67 [2] 88 4b [2] a6 69 [2] b2 72 [2] bd 68 [2] a3 75 [2] a1 74 [2] ba 72 [2] a6 75 [2] ba 5a }

  condition:
    any of them
}