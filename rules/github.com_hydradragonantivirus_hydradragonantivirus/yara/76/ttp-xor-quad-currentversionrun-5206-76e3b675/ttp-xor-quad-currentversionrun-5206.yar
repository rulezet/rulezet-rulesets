rule TTP_XOR_QUAD_CurrentVersionRun_5206 {
  strings:
    $key_5206 = { 01 69 [2] 25 67 [2] 0e 4b [2] 20 69 [2] 34 72 [2] 3b 68 [2] 25 75 [2] 27 74 [2] 3c 72 [2] 20 75 [2] 3c 5a }

  condition:
    any of them
}