rule TTP_XOR_QUAD_CurrentVersionRun_2993 {
  strings:
    $key_2993 = { 7a fc [2] 5e f2 [2] 75 de [2] 5b fc [2] 4f e7 [2] 40 fd [2] 5e e0 [2] 5c e1 [2] 47 e7 [2] 5b e0 [2] 47 cf }

  condition:
    any of them
}