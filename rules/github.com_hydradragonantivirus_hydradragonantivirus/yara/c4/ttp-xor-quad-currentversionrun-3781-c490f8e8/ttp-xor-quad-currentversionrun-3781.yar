rule TTP_XOR_QUAD_CurrentVersionRun_3781 {
  strings:
    $key_3781 = { 64 ee [2] 40 e0 [2] 6b cc [2] 45 ee [2] 51 f5 [2] 5e ef [2] 40 f2 [2] 42 f3 [2] 59 f5 [2] 45 f2 [2] 59 dd }

  condition:
    any of them
}