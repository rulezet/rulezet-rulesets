rule TTP_XOR_QUAD_CurrentVersionRun_7781 {
  strings:
    $key_7781 = { 24 ee [2] 00 e0 [2] 2b cc [2] 05 ee [2] 11 f5 [2] 1e ef [2] 00 f2 [2] 02 f3 [2] 19 f5 [2] 05 f2 [2] 19 dd }

  condition:
    any of them
}