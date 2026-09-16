rule TTP_XOR_QUAD_CurrentVersionRun_e367 {
  strings:
    $key_e367 = { b0 08 [2] 94 06 [2] bf 2a [2] 91 08 [2] 85 13 [2] 8a 09 [2] 94 14 [2] 96 15 [2] 8d 13 [2] 91 14 [2] 8d 3b }

  condition:
    any of them
}