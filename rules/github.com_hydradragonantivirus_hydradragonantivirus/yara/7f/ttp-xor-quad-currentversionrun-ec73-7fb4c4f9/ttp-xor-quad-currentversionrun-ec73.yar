rule TTP_XOR_QUAD_CurrentVersionRun_ec73 {
  strings:
    $key_ec73 = { bf 1c [2] 9b 12 [2] b0 3e [2] 9e 1c [2] 8a 07 [2] 85 1d [2] 9b 00 [2] 99 01 [2] 82 07 [2] 9e 00 [2] 82 2f }

  condition:
    any of them
}