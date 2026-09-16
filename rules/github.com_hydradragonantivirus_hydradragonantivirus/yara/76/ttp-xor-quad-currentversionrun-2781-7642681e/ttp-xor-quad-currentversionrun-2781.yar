rule TTP_XOR_QUAD_CurrentVersionRun_2781 {
  strings:
    $key_2781 = { 74 ee [2] 50 e0 [2] 7b cc [2] 55 ee [2] 41 f5 [2] 4e ef [2] 50 f2 [2] 52 f3 [2] 49 f5 [2] 55 f2 [2] 49 dd }

  condition:
    any of them
}