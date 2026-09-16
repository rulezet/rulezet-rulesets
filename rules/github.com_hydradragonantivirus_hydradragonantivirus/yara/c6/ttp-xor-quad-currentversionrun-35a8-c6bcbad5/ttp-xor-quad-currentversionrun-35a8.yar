rule TTP_XOR_QUAD_CurrentVersionRun_35a8 {
  strings:
    $key_35a8 = { 66 c7 [2] 42 c9 [2] 69 e5 [2] 47 c7 [2] 53 dc [2] 5c c6 [2] 42 db [2] 40 da [2] 5b dc [2] 47 db [2] 5b f4 }

  condition:
    any of them
}