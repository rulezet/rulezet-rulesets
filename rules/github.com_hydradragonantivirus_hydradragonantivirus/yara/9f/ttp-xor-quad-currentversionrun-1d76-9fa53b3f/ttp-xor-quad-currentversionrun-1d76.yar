rule TTP_XOR_QUAD_CurrentVersionRun_1d76 {
  strings:
    $key_1d76 = { 4e 19 [2] 6a 17 [2] 41 3b [2] 6f 19 [2] 7b 02 [2] 74 18 [2] 6a 05 [2] 68 04 [2] 73 02 [2] 6f 05 [2] 73 2a }

  condition:
    any of them
}