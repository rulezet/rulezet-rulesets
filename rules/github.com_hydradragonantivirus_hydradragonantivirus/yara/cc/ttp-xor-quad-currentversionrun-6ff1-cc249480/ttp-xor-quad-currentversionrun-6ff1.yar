rule TTP_XOR_QUAD_CurrentVersionRun_6ff1 {
  strings:
    $key_6ff1 = { 3c 9e [2] 18 90 [2] 33 bc [2] 1d 9e [2] 09 85 [2] 06 9f [2] 18 82 [2] 1a 83 [2] 01 85 [2] 1d 82 [2] 01 ad }

  condition:
    any of them
}