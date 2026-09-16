rule TTP_XOR_QUAD_CurrentVersionRun_ec05 {
  strings:
    $key_ec05 = { bf 6a [2] 9b 64 [2] b0 48 [2] 9e 6a [2] 8a 71 [2] 85 6b [2] 9b 76 [2] 99 77 [2] 82 71 [2] 9e 76 [2] 82 59 }

  condition:
    any of them
}