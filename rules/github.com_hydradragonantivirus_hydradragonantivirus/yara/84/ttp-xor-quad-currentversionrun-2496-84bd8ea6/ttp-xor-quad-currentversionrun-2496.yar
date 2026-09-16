rule TTP_XOR_QUAD_CurrentVersionRun_2496 {
  strings:
    $key_2496 = { 77 f9 [2] 53 f7 [2] 78 db [2] 56 f9 [2] 42 e2 [2] 4d f8 [2] 53 e5 [2] 51 e4 [2] 4a e2 [2] 56 e5 [2] 4a ca }

  condition:
    any of them
}