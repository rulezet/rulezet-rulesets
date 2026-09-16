rule TTP_XOR_QUAD_CurrentVersionRun_ca30 {
  strings:
    $key_ca30 = { 99 5f [2] bd 51 [2] 96 7d [2] b8 5f [2] ac 44 [2] a3 5e [2] bd 43 [2] bf 42 [2] a4 44 [2] b8 43 [2] a4 6c }

  condition:
    any of them
}