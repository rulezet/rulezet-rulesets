rule TTP_XOR_QUAD_CurrentVersionRun_1993 {
  strings:
    $key_1993 = { 4a fc [2] 6e f2 [2] 45 de [2] 6b fc [2] 7f e7 [2] 70 fd [2] 6e e0 [2] 6c e1 [2] 77 e7 [2] 6b e0 [2] 77 cf }

  condition:
    any of them
}