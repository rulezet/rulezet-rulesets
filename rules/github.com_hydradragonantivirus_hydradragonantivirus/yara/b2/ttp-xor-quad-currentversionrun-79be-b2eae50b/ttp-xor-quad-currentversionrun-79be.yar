rule TTP_XOR_QUAD_CurrentVersionRun_79be {
  strings:
    $key_79be = { 2a d1 [2] 0e df [2] 25 f3 [2] 0b d1 [2] 1f ca [2] 10 d0 [2] 0e cd [2] 0c cc [2] 17 ca [2] 0b cd [2] 17 e2 }

  condition:
    any of them
}