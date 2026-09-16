rule TTP_XOR_QUAD_CurrentVersionRun_2ba8 {
  strings:
    $key_2ba8 = { 78 c7 [2] 5c c9 [2] 77 e5 [2] 59 c7 [2] 4d dc [2] 42 c6 [2] 5c db [2] 5e da [2] 45 dc [2] 59 db [2] 45 f4 }

  condition:
    any of them
}