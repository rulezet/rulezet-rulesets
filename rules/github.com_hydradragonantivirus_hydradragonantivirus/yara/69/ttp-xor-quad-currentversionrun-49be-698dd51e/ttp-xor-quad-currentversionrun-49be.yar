rule TTP_XOR_QUAD_CurrentVersionRun_49be {
  strings:
    $key_49be = { 1a d1 [2] 3e df [2] 15 f3 [2] 3b d1 [2] 2f ca [2] 20 d0 [2] 3e cd [2] 3c cc [2] 27 ca [2] 3b cd [2] 27 e2 }

  condition:
    any of them
}