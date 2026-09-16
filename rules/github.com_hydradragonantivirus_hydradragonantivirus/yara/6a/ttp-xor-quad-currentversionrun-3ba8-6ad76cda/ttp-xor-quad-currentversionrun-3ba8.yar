rule TTP_XOR_QUAD_CurrentVersionRun_3ba8 {
  strings:
    $key_3ba8 = { 68 c7 [2] 4c c9 [2] 67 e5 [2] 49 c7 [2] 5d dc [2] 52 c6 [2] 4c db [2] 4e da [2] 55 dc [2] 49 db [2] 55 f4 }

  condition:
    any of them
}