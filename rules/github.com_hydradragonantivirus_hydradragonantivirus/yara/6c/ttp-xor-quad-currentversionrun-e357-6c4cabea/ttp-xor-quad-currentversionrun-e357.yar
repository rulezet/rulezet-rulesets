rule TTP_XOR_QUAD_CurrentVersionRun_e357 {
  strings:
    $key_e357 = { b0 38 [2] 94 36 [2] bf 1a [2] 91 38 [2] 85 23 [2] 8a 39 [2] 94 24 [2] 96 25 [2] 8d 23 [2] 91 24 [2] 8d 0b }

  condition:
    any of them
}