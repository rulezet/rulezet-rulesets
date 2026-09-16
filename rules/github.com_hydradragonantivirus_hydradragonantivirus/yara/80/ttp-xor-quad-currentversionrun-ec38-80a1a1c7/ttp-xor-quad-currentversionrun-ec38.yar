rule TTP_XOR_QUAD_CurrentVersionRun_ec38 {
  strings:
    $key_ec38 = { bf 57 [2] 9b 59 [2] b0 75 [2] 9e 57 [2] 8a 4c [2] 85 56 [2] 9b 4b [2] 99 4a [2] 82 4c [2] 9e 4b [2] 82 64 }

  condition:
    any of them
}