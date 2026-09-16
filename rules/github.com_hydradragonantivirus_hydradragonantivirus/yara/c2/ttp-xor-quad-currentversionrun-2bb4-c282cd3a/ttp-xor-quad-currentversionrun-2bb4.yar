rule TTP_XOR_QUAD_CurrentVersionRun_2bb4 {
  strings:
    $key_2bb4 = { 78 db [2] 5c d5 [2] 77 f9 [2] 59 db [2] 4d c0 [2] 42 da [2] 5c c7 [2] 5e c6 [2] 45 c0 [2] 59 c7 [2] 45 e8 }

  condition:
    any of them
}