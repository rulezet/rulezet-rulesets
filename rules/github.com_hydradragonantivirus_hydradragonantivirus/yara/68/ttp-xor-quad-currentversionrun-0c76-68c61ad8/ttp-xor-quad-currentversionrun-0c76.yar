rule TTP_XOR_QUAD_CurrentVersionRun_0c76 {
  strings:
    $key_0c76 = { 5f 19 [2] 7b 17 [2] 50 3b [2] 7e 19 [2] 6a 02 [2] 65 18 [2] 7b 05 [2] 79 04 [2] 62 02 [2] 7e 05 [2] 62 2a }

  condition:
    any of them
}