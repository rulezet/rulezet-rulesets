rule TTP_XOR_QUAD_CurrentVersionRun_3176 {
  strings:
    $key_3176 = { 62 19 [2] 46 17 [2] 6d 3b [2] 43 19 [2] 57 02 [2] 58 18 [2] 46 05 [2] 44 04 [2] 5f 02 [2] 43 05 [2] 5f 2a }

  condition:
    any of them
}