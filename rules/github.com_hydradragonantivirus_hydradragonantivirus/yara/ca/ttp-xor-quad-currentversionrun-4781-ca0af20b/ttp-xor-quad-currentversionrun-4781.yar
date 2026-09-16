rule TTP_XOR_QUAD_CurrentVersionRun_4781 {
  strings:
    $key_4781 = { 14 ee [2] 30 e0 [2] 1b cc [2] 35 ee [2] 21 f5 [2] 2e ef [2] 30 f2 [2] 32 f3 [2] 29 f5 [2] 35 f2 [2] 29 dd }

  condition:
    any of them
}