rule TTP_XOR_QUAD_CurrentVersionRun_35b3 {
  strings:
    $key_35b3 = { 66 dc [2] 42 d2 [2] 69 fe [2] 47 dc [2] 53 c7 [2] 5c dd [2] 42 c0 [2] 40 c1 [2] 5b c7 [2] 47 c0 [2] 5b ef }

  condition:
    any of them
}