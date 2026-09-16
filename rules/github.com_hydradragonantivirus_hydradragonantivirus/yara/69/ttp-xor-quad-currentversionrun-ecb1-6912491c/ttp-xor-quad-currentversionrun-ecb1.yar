rule TTP_XOR_QUAD_CurrentVersionRun_ecb1 {
  strings:
    $key_ecb1 = { bf de [2] 9b d0 [2] b0 fc [2] 9e de [2] 8a c5 [2] 85 df [2] 9b c2 [2] 99 c3 [2] 82 c5 [2] 9e c2 [2] 82 ed }

  condition:
    any of them
}