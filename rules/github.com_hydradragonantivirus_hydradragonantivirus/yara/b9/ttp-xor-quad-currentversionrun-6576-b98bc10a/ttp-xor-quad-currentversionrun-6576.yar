rule TTP_XOR_QUAD_CurrentVersionRun_6576 {
  strings:
    $key_6576 = { 36 19 [2] 12 17 [2] 39 3b [2] 17 19 [2] 03 02 [2] 0c 18 [2] 12 05 [2] 10 04 [2] 0b 02 [2] 17 05 [2] 0b 2a }

  condition:
    any of them
}