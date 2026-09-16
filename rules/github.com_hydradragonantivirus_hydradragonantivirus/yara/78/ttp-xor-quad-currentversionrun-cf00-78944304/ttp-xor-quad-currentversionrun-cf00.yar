rule TTP_XOR_QUAD_CurrentVersionRun_cf00 {
  strings:
    $key_cf00 = { 9c 6f [2] b8 61 [2] 93 4d [2] bd 6f [2] a9 74 [2] a6 6e [2] b8 73 [2] ba 72 [2] a1 74 [2] bd 73 [2] a1 5c }

  condition:
    any of them
}