rule TTP_XOR_QUAD_CurrentVersionRun_7ff1 {
  strings:
    $key_7ff1 = { 2c 9e [2] 08 90 [2] 23 bc [2] 0d 9e [2] 19 85 [2] 16 9f [2] 08 82 [2] 0a 83 [2] 11 85 [2] 0d 82 [2] 11 ad }

  condition:
    any of them
}