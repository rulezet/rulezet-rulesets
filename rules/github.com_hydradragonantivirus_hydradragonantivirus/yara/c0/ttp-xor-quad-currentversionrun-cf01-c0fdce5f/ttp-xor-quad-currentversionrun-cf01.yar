rule TTP_XOR_QUAD_CurrentVersionRun_cf01 {
  strings:
    $key_cf01 = { 9c 6e [2] b8 60 [2] 93 4c [2] bd 6e [2] a9 75 [2] a6 6f [2] b8 72 [2] ba 73 [2] a1 75 [2] bd 72 [2] a1 5d }

  condition:
    any of them
}