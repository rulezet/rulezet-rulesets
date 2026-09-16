rule TTP_XOR_QUAD_CurrentVersionRun_c831 {
  strings:
    $key_c831 = { 9b 5e [2] bf 50 [2] 94 7c [2] ba 5e [2] ae 45 [2] a1 5f [2] bf 42 [2] bd 43 [2] a6 45 [2] ba 42 [2] a6 6d }

  condition:
    any of them
}