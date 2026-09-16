rule TTP_XOR_QUAD_CurrentVersionRun_6f07 {
  strings:
    $key_6f07 = { 3c 68 [2] 18 66 [2] 33 4a [2] 1d 68 [2] 09 73 [2] 06 69 [2] 18 74 [2] 1a 75 [2] 01 73 [2] 1d 74 [2] 01 5b }

  condition:
    any of them
}