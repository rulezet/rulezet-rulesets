rule TTP_XOR_QUAD_CurrentVersionRun_64b3 {
  strings:
    $key_64b3 = { 37 dc [2] 13 d2 [2] 38 fe [2] 16 dc [2] 02 c7 [2] 0d dd [2] 13 c0 [2] 11 c1 [2] 0a c7 [2] 16 c0 [2] 0a ef }

  condition:
    any of them
}