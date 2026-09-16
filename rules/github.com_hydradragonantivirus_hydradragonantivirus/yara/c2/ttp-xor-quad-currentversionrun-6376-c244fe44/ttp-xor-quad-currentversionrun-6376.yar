rule TTP_XOR_QUAD_CurrentVersionRun_6376 {
  strings:
    $key_6376 = { 30 19 [2] 14 17 [2] 3f 3b [2] 11 19 [2] 05 02 [2] 0a 18 [2] 14 05 [2] 16 04 [2] 0d 02 [2] 11 05 [2] 0d 2a }

  condition:
    any of them
}