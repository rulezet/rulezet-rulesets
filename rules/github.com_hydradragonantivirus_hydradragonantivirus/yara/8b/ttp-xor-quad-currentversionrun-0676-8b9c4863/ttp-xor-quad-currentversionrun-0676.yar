rule TTP_XOR_QUAD_CurrentVersionRun_0676 {
  strings:
    $key_0676 = { 55 19 [2] 71 17 [2] 5a 3b [2] 74 19 [2] 60 02 [2] 6f 18 [2] 71 05 [2] 73 04 [2] 68 02 [2] 74 05 [2] 68 2a }

  condition:
    any of them
}