rule TTP_XOR_QUAD_CurrentVersionRun_ec25 {
  strings:
    $key_ec25 = { bf 4a [2] 9b 44 [2] b0 68 [2] 9e 4a [2] 8a 51 [2] 85 4b [2] 9b 56 [2] 99 57 [2] 82 51 [2] 9e 56 [2] 82 79 }

  condition:
    any of them
}