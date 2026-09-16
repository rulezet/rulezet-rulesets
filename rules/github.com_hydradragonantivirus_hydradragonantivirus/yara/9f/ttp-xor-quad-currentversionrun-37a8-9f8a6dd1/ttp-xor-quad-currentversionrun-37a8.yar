rule TTP_XOR_QUAD_CurrentVersionRun_37a8 {
  strings:
    $key_37a8 = { 64 c7 [2] 40 c9 [2] 6b e5 [2] 45 c7 [2] 51 dc [2] 5e c6 [2] 40 db [2] 42 da [2] 59 dc [2] 45 db [2] 59 f4 }

  condition:
    any of them
}