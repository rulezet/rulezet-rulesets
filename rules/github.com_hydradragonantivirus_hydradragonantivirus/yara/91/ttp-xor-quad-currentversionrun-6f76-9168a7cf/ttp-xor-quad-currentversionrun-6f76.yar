rule TTP_XOR_QUAD_CurrentVersionRun_6f76 {
  strings:
    $key_6f76 = { 3c 19 [2] 18 17 [2] 33 3b [2] 1d 19 [2] 09 02 [2] 06 18 [2] 18 05 [2] 1a 04 [2] 01 02 [2] 1d 05 [2] 01 2a }

  condition:
    any of them
}