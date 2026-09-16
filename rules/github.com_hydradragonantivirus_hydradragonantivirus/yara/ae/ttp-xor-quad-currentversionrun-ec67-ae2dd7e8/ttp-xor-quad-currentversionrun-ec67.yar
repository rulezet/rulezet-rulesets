rule TTP_XOR_QUAD_CurrentVersionRun_ec67 {
  strings:
    $key_ec67 = { bf 08 [2] 9b 06 [2] b0 2a [2] 9e 08 [2] 8a 13 [2] 85 09 [2] 9b 14 [2] 99 15 [2] 82 13 [2] 9e 14 [2] 82 3b }

  condition:
    any of them
}