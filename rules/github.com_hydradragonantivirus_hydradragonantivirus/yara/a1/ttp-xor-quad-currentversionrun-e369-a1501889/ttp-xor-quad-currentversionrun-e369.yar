rule TTP_XOR_QUAD_CurrentVersionRun_e369 {
  strings:
    $key_e369 = { b0 06 [2] 94 08 [2] bf 24 [2] 91 06 [2] 85 1d [2] 8a 07 [2] 94 1a [2] 96 1b [2] 8d 1d [2] 91 1a [2] 8d 35 }

  condition:
    any of them
}