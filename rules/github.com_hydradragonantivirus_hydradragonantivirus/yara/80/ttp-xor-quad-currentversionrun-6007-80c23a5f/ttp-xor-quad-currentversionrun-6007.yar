rule TTP_XOR_QUAD_CurrentVersionRun_6007 {
  strings:
    $key_6007 = { 33 68 [2] 17 66 [2] 3c 4a [2] 12 68 [2] 06 73 [2] 09 69 [2] 17 74 [2] 15 75 [2] 0e 73 [2] 12 74 [2] 0e 5b }

  condition:
    any of them
}