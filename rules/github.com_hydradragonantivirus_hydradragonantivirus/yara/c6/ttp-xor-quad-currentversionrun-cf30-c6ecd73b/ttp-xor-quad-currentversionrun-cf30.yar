rule TTP_XOR_QUAD_CurrentVersionRun_cf30 {
  strings:
    $key_cf30 = { 9c 5f [2] b8 51 [2] 93 7d [2] bd 5f [2] a9 44 [2] a6 5e [2] b8 43 [2] ba 42 [2] a1 44 [2] bd 43 [2] a1 6c }

  condition:
    any of them
}