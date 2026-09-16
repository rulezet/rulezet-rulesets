rule TTP_XOR_QUAD_CurrentVersionRun_5777 {
  strings:
    $key_5777 = { 04 18 [2] 20 16 [2] 0b 3a [2] 25 18 [2] 31 03 [2] 3e 19 [2] 20 04 [2] 22 05 [2] 39 03 [2] 25 04 [2] 39 2b }

  condition:
    any of them
}