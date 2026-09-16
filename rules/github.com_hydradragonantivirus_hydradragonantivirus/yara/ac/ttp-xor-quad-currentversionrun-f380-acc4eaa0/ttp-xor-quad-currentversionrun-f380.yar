rule TTP_XOR_QUAD_CurrentVersionRun_f380 {
  strings:
    $key_f380 = { a0 ef [2] 84 e1 [2] af cd [2] 81 ef [2] 95 f4 [2] 9a ee [2] 84 f3 [2] 86 f2 [2] 9d f4 [2] 81 f3 [2] 9d dc }

  condition:
    any of them
}