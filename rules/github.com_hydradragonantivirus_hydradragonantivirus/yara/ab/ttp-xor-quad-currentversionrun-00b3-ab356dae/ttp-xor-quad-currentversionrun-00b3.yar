rule TTP_XOR_QUAD_CurrentVersionRun_00b3 {
  strings:
    $key_00b3 = { 53 dc [2] 77 d2 [2] 5c fe [2] 72 dc [2] 66 c7 [2] 69 dd [2] 77 c0 [2] 75 c1 [2] 6e c7 [2] 72 c0 [2] 6e ef }

  condition:
    any of them
}