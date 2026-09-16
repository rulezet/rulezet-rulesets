rule TTP_XOR_QUAD_CurrentVersionRun_e3a3 {
  strings:
    $key_e3a3 = { b0 cc [2] 94 c2 [2] bf ee [2] 91 cc [2] 85 d7 [2] 8a cd [2] 94 d0 [2] 96 d1 [2] 8d d7 [2] 91 d0 [2] 8d ff }

  condition:
    any of them
}