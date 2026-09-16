rule TTP_XOR_QUAD_CurrentVersionRun_74b3 {
  strings:
    $key_74b3 = { 27 dc [2] 03 d2 [2] 28 fe [2] 06 dc [2] 12 c7 [2] 1d dd [2] 03 c0 [2] 01 c1 [2] 1a c7 [2] 06 c0 [2] 1a ef }

  condition:
    any of them
}