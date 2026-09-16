rule TTP_XOR_QUAD_CurrentVersionRun_6277 {
  strings:
    $key_6277 = { 31 18 [2] 15 16 [2] 3e 3a [2] 10 18 [2] 04 03 [2] 0b 19 [2] 15 04 [2] 17 05 [2] 0c 03 [2] 10 04 [2] 0c 2b }

  condition:
    any of them
}