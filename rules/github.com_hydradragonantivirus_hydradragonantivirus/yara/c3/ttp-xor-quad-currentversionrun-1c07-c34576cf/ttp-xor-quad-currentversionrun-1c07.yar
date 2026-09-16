rule TTP_XOR_QUAD_CurrentVersionRun_1c07 {
  strings:
    $key_1c07 = { 4f 68 [2] 6b 66 [2] 40 4a [2] 6e 68 [2] 7a 73 [2] 75 69 [2] 6b 74 [2] 69 75 [2] 72 73 [2] 6e 74 [2] 72 5b }

  condition:
    any of them
}