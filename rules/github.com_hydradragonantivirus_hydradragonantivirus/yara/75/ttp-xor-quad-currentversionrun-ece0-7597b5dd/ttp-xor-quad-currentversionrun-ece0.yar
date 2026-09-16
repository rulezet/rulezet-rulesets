rule TTP_XOR_QUAD_CurrentVersionRun_ece0 {
  strings:
    $key_ece0 = { bf 8f [2] 9b 81 [2] b0 ad [2] 9e 8f [2] 8a 94 [2] 85 8e [2] 9b 93 [2] 99 92 [2] 82 94 [2] 9e 93 [2] 82 bc }

  condition:
    any of them
}