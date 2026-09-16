rule TTP_XOR_QUAD_CurrentVersionRun_4c06 {
  strings:
    $key_4c06 = { 1f 69 [2] 3b 67 [2] 10 4b [2] 3e 69 [2] 2a 72 [2] 25 68 [2] 3b 75 [2] 39 74 [2] 22 72 [2] 3e 75 [2] 22 5a }

  condition:
    any of them
}