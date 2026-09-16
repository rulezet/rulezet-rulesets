rule TTP_XOR_QUAD_CurrentVersionRun_d330 {
  strings:
    $key_d330 = { 80 5f [2] a4 51 [2] 8f 7d [2] a1 5f [2] b5 44 [2] ba 5e [2] a4 43 [2] a6 42 [2] bd 44 [2] a1 43 [2] bd 6c }

  condition:
    any of them
}