rule TTP_XOR_QUAD_CurrentVersionRun_6df1 {
  strings:
    $key_6df1 = { 3e 9e [2] 1a 90 [2] 31 bc [2] 1f 9e [2] 0b 85 [2] 04 9f [2] 1a 82 [2] 18 83 [2] 03 85 [2] 1f 82 [2] 03 ad }

  condition:
    any of them
}