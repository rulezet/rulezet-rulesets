rule TTP_XOR_QUAD_CurrentVersionRun_3606 {
  strings:
    $key_3606 = { 65 69 [2] 41 67 [2] 6a 4b [2] 44 69 [2] 50 72 [2] 5f 68 [2] 41 75 [2] 43 74 [2] 58 72 [2] 44 75 [2] 58 5a }

  condition:
    any of them
}