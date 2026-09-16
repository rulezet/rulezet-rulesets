rule TTP_XOR_QUAD_CurrentVersionRun_5577 {
  strings:
    $key_5577 = { 06 18 [2] 22 16 [2] 09 3a [2] 27 18 [2] 33 03 [2] 3c 19 [2] 22 04 [2] 20 05 [2] 3b 03 [2] 27 04 [2] 3b 2b }

  condition:
    any of them
}