rule TTP_XOR_QUAD_CurrentVersionRun_ec78 {
  strings:
    $key_ec78 = { bf 17 [2] 9b 19 [2] b0 35 [2] 9e 17 [2] 8a 0c [2] 85 16 [2] 9b 0b [2] 99 0a [2] 82 0c [2] 9e 0b [2] 82 24 }

  condition:
    any of them
}