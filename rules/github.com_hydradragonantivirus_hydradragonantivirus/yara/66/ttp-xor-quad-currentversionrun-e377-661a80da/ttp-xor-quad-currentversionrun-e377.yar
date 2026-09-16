rule TTP_XOR_QUAD_CurrentVersionRun_e377 {
  strings:
    $key_e377 = { b0 18 [2] 94 16 [2] bf 3a [2] 91 18 [2] 85 03 [2] 8a 19 [2] 94 04 [2] 96 05 [2] 8d 03 [2] 91 04 [2] 8d 2b }

  condition:
    any of them
}