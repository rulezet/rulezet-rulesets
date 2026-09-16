rule TTP_XOR_QUAD_CurrentVersionRun_ec3b {
  strings:
    $key_ec3b = { bf 54 [2] 9b 5a [2] b0 76 [2] 9e 54 [2] 8a 4f [2] 85 55 [2] 9b 48 [2] 99 49 [2] 82 4f [2] 9e 48 [2] 82 67 }

  condition:
    any of them
}