rule TTP_XOR_QUAD_CurrentVersionRun_ec26 {
  strings:
    $key_ec26 = { bf 49 [2] 9b 47 [2] b0 6b [2] 9e 49 [2] 8a 52 [2] 85 48 [2] 9b 55 [2] 99 54 [2] 82 52 [2] 9e 55 [2] 82 7a }

  condition:
    any of them
}