rule TTP_XOR_QUAD_CurrentVersionRun_f2a3 {
  strings:
    $key_f2a3 = { a1 cc [2] 85 c2 [2] ae ee [2] 80 cc [2] 94 d7 [2] 9b cd [2] 85 d0 [2] 87 d1 [2] 9c d7 [2] 80 d0 [2] 9c ff }

  condition:
    any of them
}