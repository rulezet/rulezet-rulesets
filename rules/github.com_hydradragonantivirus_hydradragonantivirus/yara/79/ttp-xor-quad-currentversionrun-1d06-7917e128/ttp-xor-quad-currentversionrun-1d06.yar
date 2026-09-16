rule TTP_XOR_QUAD_CurrentVersionRun_1d06 {
  strings:
    $key_1d06 = { 4e 69 [2] 6a 67 [2] 41 4b [2] 6f 69 [2] 7b 72 [2] 74 68 [2] 6a 75 [2] 68 74 [2] 73 72 [2] 6f 75 [2] 73 5a }

  condition:
    any of them
}