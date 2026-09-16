rule TTP_XOR_QUAD_CurrentVersionRun_6807 {
  strings:
    $key_6807 = { 3b 68 [2] 1f 66 [2] 34 4a [2] 1a 68 [2] 0e 73 [2] 01 69 [2] 1f 74 [2] 1d 75 [2] 06 73 [2] 1a 74 [2] 06 5b }

  condition:
    any of them
}