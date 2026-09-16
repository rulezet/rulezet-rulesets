rule TTP_XOR_QUAD_CurrentVersionRun_6b57 {
  strings:
    $key_6b57 = { 38 38 [2] 1c 36 [2] 37 1a [2] 19 38 [2] 0d 23 [2] 02 39 [2] 1c 24 [2] 1e 25 [2] 05 23 [2] 19 24 [2] 05 0b }

  condition:
    any of them
}