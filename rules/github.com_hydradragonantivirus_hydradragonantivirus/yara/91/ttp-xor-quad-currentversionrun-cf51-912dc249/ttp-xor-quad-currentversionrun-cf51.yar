rule TTP_XOR_QUAD_CurrentVersionRun_cf51 {
  strings:
    $key_cf51 = { 9c 3e [2] b8 30 [2] 93 1c [2] bd 3e [2] a9 25 [2] a6 3f [2] b8 22 [2] ba 23 [2] a1 25 [2] bd 22 [2] a1 0d }

  condition:
    any of them
}