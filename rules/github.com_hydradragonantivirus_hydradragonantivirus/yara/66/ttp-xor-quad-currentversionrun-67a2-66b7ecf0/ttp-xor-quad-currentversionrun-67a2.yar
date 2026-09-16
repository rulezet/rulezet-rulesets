rule TTP_XOR_QUAD_CurrentVersionRun_67a2 {
  strings:
    $key_67a2 = { 34 cd [2] 10 c3 [2] 3b ef [2] 15 cd [2] 01 d6 [2] 0e cc [2] 10 d1 [2] 12 d0 [2] 09 d6 [2] 15 d1 [2] 09 fe }

  condition:
    any of them
}