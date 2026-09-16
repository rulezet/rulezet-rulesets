rule TTP_XOR_QUAD_CurrentVersionRun_ec41 {
  strings:
    $key_ec41 = { bf 2e [2] 9b 20 [2] b0 0c [2] 9e 2e [2] 8a 35 [2] 85 2f [2] 9b 32 [2] 99 33 [2] 82 35 [2] 9e 32 [2] 82 1d }

  condition:
    any of them
}