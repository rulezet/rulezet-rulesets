rule TTP_XOR_QUAD_CurrentVersionRun_27a2 {
  strings:
    $key_27a2 = { 74 cd [2] 50 c3 [2] 7b ef [2] 55 cd [2] 41 d6 [2] 4e cc [2] 50 d1 [2] 52 d0 [2] 49 d6 [2] 55 d1 [2] 49 fe }

  condition:
    any of them
}