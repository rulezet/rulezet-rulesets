rule TTP_XOR_QUAD_CurrentVersionRun_6476 {
  strings:
    $key_6476 = { 37 19 [2] 13 17 [2] 38 3b [2] 16 19 [2] 02 02 [2] 0d 18 [2] 13 05 [2] 11 04 [2] 0a 02 [2] 16 05 [2] 0a 2a }

  condition:
    any of them
}