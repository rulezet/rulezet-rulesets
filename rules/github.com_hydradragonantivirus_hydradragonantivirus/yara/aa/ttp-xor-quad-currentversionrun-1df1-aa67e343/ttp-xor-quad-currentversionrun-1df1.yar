rule TTP_XOR_QUAD_CurrentVersionRun_1df1 {
  strings:
    $key_1df1 = { 4e 9e [2] 6a 90 [2] 41 bc [2] 6f 9e [2] 7b 85 [2] 74 9f [2] 6a 82 [2] 68 83 [2] 73 85 [2] 6f 82 [2] 73 ad }

  condition:
    any of them
}