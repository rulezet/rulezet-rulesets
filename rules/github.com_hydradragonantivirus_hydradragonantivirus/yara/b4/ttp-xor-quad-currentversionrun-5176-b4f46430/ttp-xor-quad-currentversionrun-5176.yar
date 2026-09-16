rule TTP_XOR_QUAD_CurrentVersionRun_5176 {
  strings:
    $key_5176 = { 02 19 [2] 26 17 [2] 0d 3b [2] 23 19 [2] 37 02 [2] 38 18 [2] 26 05 [2] 24 04 [2] 3f 02 [2] 23 05 [2] 3f 2a }

  condition:
    any of them
}