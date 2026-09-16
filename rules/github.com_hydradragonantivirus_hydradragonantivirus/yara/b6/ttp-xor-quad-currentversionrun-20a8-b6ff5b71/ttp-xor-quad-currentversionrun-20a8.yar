rule TTP_XOR_QUAD_CurrentVersionRun_20a8 {
  strings:
    $key_20a8 = { 73 c7 [2] 57 c9 [2] 7c e5 [2] 52 c7 [2] 46 dc [2] 49 c6 [2] 57 db [2] 55 da [2] 4e dc [2] 52 db [2] 4e f4 }

  condition:
    any of them
}