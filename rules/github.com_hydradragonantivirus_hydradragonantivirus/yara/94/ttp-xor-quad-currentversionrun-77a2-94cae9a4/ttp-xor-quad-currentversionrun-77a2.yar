rule TTP_XOR_QUAD_CurrentVersionRun_77a2 {
  strings:
    $key_77a2 = { 24 cd [2] 00 c3 [2] 2b ef [2] 05 cd [2] 11 d6 [2] 1e cc [2] 00 d1 [2] 02 d0 [2] 19 d6 [2] 05 d1 [2] 19 fe }

  condition:
    any of them
}