rule TTP_XOR_QUAD_CurrentVersionRun_ec76 {
  strings:
    $key_ec76 = { bf 19 [2] 9b 17 [2] b0 3b [2] 9e 19 [2] 8a 02 [2] 85 18 [2] 9b 05 [2] 99 04 [2] 82 02 [2] 9e 05 [2] 82 2a }

  condition:
    any of them
}