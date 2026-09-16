rule TTP_XOR_QUAD_CurrentVersionRun_45b3 {
  strings:
    $key_45b3 = { 16 dc [2] 32 d2 [2] 19 fe [2] 37 dc [2] 23 c7 [2] 2c dd [2] 32 c0 [2] 30 c1 [2] 2b c7 [2] 37 c0 [2] 2b ef }

  condition:
    any of them
}