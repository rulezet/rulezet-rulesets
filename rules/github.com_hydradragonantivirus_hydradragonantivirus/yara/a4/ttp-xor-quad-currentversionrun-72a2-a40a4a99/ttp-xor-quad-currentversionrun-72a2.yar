rule TTP_XOR_QUAD_CurrentVersionRun_72a2 {
  strings:
    $key_72a2 = { 21 cd [2] 05 c3 [2] 2e ef [2] 00 cd [2] 14 d6 [2] 1b cc [2] 05 d1 [2] 07 d0 [2] 1c d6 [2] 00 d1 [2] 1c fe }

  condition:
    any of them
}