rule TTP_XOR_QUAD_CurrentVersionRun_1181 {
  strings:
    $key_1181 = { 42 ee [2] 66 e0 [2] 4d cc [2] 63 ee [2] 77 f5 [2] 78 ef [2] 66 f2 [2] 64 f3 [2] 7f f5 [2] 63 f2 [2] 7f dd }

  condition:
    any of them
}