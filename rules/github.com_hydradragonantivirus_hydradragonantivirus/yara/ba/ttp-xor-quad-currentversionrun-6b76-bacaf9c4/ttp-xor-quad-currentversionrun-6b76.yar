rule TTP_XOR_QUAD_CurrentVersionRun_6b76 {
  strings:
    $key_6b76 = { 38 19 [2] 1c 17 [2] 37 3b [2] 19 19 [2] 0d 02 [2] 02 18 [2] 1c 05 [2] 1e 04 [2] 05 02 [2] 19 05 [2] 05 2a }

  condition:
    any of them
}