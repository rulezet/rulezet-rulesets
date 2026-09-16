rule TTP_XOR_QUAD_CurrentVersionRun_75b3 {
  strings:
    $key_75b3 = { 26 dc [2] 02 d2 [2] 29 fe [2] 07 dc [2] 13 c7 [2] 1c dd [2] 02 c0 [2] 00 c1 [2] 1b c7 [2] 07 c0 [2] 1b ef }

  condition:
    any of them
}