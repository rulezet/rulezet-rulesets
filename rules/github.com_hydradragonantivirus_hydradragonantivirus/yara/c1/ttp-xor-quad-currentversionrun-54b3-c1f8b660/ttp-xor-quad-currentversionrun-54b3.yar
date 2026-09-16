rule TTP_XOR_QUAD_CurrentVersionRun_54b3 {
  strings:
    $key_54b3 = { 07 dc [2] 23 d2 [2] 08 fe [2] 26 dc [2] 32 c7 [2] 3d dd [2] 23 c0 [2] 21 c1 [2] 3a c7 [2] 26 c0 [2] 3a ef }

  condition:
    any of them
}