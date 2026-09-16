rule TTP_XOR_QUAD_CurrentVersionRun_00a8 {
  strings:
    $key_00a8 = { 53 c7 [2] 77 c9 [2] 5c e5 [2] 72 c7 [2] 66 dc [2] 69 c6 [2] 77 db [2] 75 da [2] 6e dc [2] 72 db [2] 6e f4 }

  condition:
    any of them
}