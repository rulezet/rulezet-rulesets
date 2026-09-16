rule TTP_XOR_QUAD_CurrentVersionRun_ec66 {
  strings:
    $key_ec66 = { bf 09 [2] 9b 07 [2] b0 2b [2] 9e 09 [2] 8a 12 [2] 85 08 [2] 9b 15 [2] 99 14 [2] 82 12 [2] 9e 15 [2] 82 3a }

  condition:
    any of them
}