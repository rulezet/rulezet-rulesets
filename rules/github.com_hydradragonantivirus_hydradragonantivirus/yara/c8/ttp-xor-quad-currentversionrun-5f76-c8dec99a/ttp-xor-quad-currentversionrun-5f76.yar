rule TTP_XOR_QUAD_CurrentVersionRun_5f76 {
  strings:
    $key_5f76 = { 0c 19 [2] 28 17 [2] 03 3b [2] 2d 19 [2] 39 02 [2] 36 18 [2] 28 05 [2] 2a 04 [2] 31 02 [2] 2d 05 [2] 31 2a }

  condition:
    any of them
}