rule TTP_XOR_QUAD_CurrentVersionRun_2f76 {
  strings:
    $key_2f76 = { 7c 19 [2] 58 17 [2] 73 3b [2] 5d 19 [2] 49 02 [2] 46 18 [2] 58 05 [2] 5a 04 [2] 41 02 [2] 5d 05 [2] 41 2a }

  condition:
    any of them
}