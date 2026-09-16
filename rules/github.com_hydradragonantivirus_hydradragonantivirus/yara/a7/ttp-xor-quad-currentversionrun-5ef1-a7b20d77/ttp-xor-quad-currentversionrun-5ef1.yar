rule TTP_XOR_QUAD_CurrentVersionRun_5ef1 {
  strings:
    $key_5ef1 = { 0d 9e [2] 29 90 [2] 02 bc [2] 2c 9e [2] 38 85 [2] 37 9f [2] 29 82 [2] 2b 83 [2] 30 85 [2] 2c 82 [2] 30 ad }

  condition:
    any of them
}