rule TTP_XOR_QUAD_CurrentVersionRun_2076 {
  strings:
    $key_2076 = { 73 19 [2] 57 17 [2] 7c 3b [2] 52 19 [2] 46 02 [2] 49 18 [2] 57 05 [2] 55 04 [2] 4e 02 [2] 52 05 [2] 4e 2a }

  condition:
    any of them
}