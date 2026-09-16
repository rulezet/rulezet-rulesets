rule TTP_XOR_QUAD_CurrentVersionRun_55a8 {
  strings:
    $key_55a8 = { 06 c7 [2] 22 c9 [2] 09 e5 [2] 27 c7 [2] 33 dc [2] 3c c6 [2] 22 db [2] 20 da [2] 3b dc [2] 27 db [2] 3b f4 }

  condition:
    any of them
}