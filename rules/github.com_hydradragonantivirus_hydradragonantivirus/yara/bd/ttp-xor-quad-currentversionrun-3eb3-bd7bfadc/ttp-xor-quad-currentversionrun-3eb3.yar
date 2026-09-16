rule TTP_XOR_QUAD_CurrentVersionRun_3eb3 {
  strings:
    $key_3eb3 = { 6d dc [2] 49 d2 [2] 62 fe [2] 4c dc [2] 58 c7 [2] 57 dd [2] 49 c0 [2] 4b c1 [2] 50 c7 [2] 4c c0 [2] 50 ef }

  condition:
    any of them
}