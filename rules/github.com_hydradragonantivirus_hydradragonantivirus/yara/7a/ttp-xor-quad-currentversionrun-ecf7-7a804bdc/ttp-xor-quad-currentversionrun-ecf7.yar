rule TTP_XOR_QUAD_CurrentVersionRun_ecf7 {
  strings:
    $key_ecf7 = { bf 98 [2] 9b 96 [2] b0 ba [2] 9e 98 [2] 8a 83 [2] 85 99 [2] 9b 84 [2] 99 85 [2] 82 83 [2] 9e 84 [2] 82 ab }

  condition:
    any of them
}