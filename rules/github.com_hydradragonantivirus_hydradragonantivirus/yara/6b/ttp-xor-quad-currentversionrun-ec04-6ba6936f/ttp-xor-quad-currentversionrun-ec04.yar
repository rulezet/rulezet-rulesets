rule TTP_XOR_QUAD_CurrentVersionRun_ec04 {
  strings:
    $key_ec04 = { bf 6b [2] 9b 65 [2] b0 49 [2] 9e 6b [2] 8a 70 [2] 85 6a [2] 9b 77 [2] 99 76 [2] 82 70 [2] 9e 77 [2] 82 58 }

  condition:
    any of them
}