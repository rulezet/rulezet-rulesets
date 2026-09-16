rule TTP_XOR_QUAD_CurrentVersionRun_5df1 {
  strings:
    $key_5df1 = { 0e 9e [2] 2a 90 [2] 01 bc [2] 2f 9e [2] 3b 85 [2] 34 9f [2] 2a 82 [2] 28 83 [2] 33 85 [2] 2f 82 [2] 33 ad }

  condition:
    any of them
}