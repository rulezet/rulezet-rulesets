rule TTP_XOR_QUAD_CurrentVersionRun_ec15 {
  strings:
    $key_ec15 = { bf 7a [2] 9b 74 [2] b0 58 [2] 9e 7a [2] 8a 61 [2] 85 7b [2] 9b 66 [2] 99 67 [2] 82 61 [2] 9e 66 [2] 82 49 }

  condition:
    any of them
}