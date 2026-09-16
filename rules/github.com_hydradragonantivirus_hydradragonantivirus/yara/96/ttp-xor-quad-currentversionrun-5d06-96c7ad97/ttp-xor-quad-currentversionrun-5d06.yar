rule TTP_XOR_QUAD_CurrentVersionRun_5d06 {
  strings:
    $key_5d06 = { 0e 69 [2] 2a 67 [2] 01 4b [2] 2f 69 [2] 3b 72 [2] 34 68 [2] 2a 75 [2] 28 74 [2] 33 72 [2] 2f 75 [2] 33 5a }

  condition:
    any of them
}