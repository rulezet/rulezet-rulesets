rule TTP_XOR_QUAD_CurrentVersionRun_2576 {
  strings:
    $key_2576 = { 76 19 [2] 52 17 [2] 79 3b [2] 57 19 [2] 43 02 [2] 4c 18 [2] 52 05 [2] 50 04 [2] 4b 02 [2] 57 05 [2] 4b 2a }

  condition:
    any of them
}