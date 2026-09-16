rule TTP_XOR_QUAD_CurrentVersionRun_ec17 {
  strings:
    $key_ec17 = { bf 78 [2] 9b 76 [2] b0 5a [2] 9e 78 [2] 8a 63 [2] 85 79 [2] 9b 64 [2] 99 65 [2] 82 63 [2] 9e 64 [2] 82 4b }

  condition:
    any of them
}