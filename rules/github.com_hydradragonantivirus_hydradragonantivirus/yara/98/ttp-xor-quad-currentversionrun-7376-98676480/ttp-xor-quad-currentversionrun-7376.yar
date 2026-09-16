rule TTP_XOR_QUAD_CurrentVersionRun_7376 {
  strings:
    $key_7376 = { 20 19 [2] 04 17 [2] 2f 3b [2] 01 19 [2] 15 02 [2] 1a 18 [2] 04 05 [2] 06 04 [2] 1d 02 [2] 01 05 [2] 1d 2a }

  condition:
    any of them
}