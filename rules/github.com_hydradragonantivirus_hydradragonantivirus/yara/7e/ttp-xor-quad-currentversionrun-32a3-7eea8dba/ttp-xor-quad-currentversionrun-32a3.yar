rule TTP_XOR_QUAD_CurrentVersionRun_32a3 {
  strings:
    $key_32a3 = { 61 cc [2] 45 c2 [2] 6e ee [2] 40 cc [2] 54 d7 [2] 5b cd [2] 45 d0 [2] 47 d1 [2] 5c d7 [2] 40 d0 [2] 5c ff }

  condition:
    any of them
}