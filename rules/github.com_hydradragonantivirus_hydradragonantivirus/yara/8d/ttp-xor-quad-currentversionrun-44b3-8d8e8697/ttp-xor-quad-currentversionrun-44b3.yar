rule TTP_XOR_QUAD_CurrentVersionRun_44b3 {
  strings:
    $key_44b3 = { 17 dc [2] 33 d2 [2] 18 fe [2] 36 dc [2] 22 c7 [2] 2d dd [2] 33 c0 [2] 31 c1 [2] 2a c7 [2] 36 c0 [2] 2a ef }

  condition:
    any of them
}