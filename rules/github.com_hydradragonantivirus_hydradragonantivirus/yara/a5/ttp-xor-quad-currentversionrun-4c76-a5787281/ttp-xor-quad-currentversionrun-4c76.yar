rule TTP_XOR_QUAD_CurrentVersionRun_4c76 {
  strings:
    $key_4c76 = { 1f 19 [2] 3b 17 [2] 10 3b [2] 3e 19 [2] 2a 02 [2] 25 18 [2] 3b 05 [2] 39 04 [2] 22 02 [2] 3e 05 [2] 22 2a }

  condition:
    any of them
}