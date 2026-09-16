rule TTP_XOR_QUAD_CurrentVersionRun_7181 {
  strings:
    $key_7181 = { 22 ee [2] 06 e0 [2] 2d cc [2] 03 ee [2] 17 f5 [2] 18 ef [2] 06 f2 [2] 04 f3 [2] 1f f5 [2] 03 f2 [2] 1f dd }

  condition:
    any of them
}