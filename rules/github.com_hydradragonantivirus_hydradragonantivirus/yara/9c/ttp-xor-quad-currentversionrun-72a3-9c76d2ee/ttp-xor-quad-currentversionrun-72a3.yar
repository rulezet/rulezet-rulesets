rule TTP_XOR_QUAD_CurrentVersionRun_72a3 {
  strings:
    $key_72a3 = { 21 cc [2] 05 c2 [2] 2e ee [2] 00 cc [2] 14 d7 [2] 1b cd [2] 05 d0 [2] 07 d1 [2] 1c d7 [2] 00 d0 [2] 1c ff }

  condition:
    any of them
}