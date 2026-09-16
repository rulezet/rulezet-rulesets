rule TTP_XOR_QUAD_CurrentVersionRun_5076 {
  strings:
    $key_5076 = { 03 19 [2] 27 17 [2] 0c 3b [2] 22 19 [2] 36 02 [2] 39 18 [2] 27 05 [2] 25 04 [2] 3e 02 [2] 22 05 [2] 3e 2a }

  condition:
    any of them
}