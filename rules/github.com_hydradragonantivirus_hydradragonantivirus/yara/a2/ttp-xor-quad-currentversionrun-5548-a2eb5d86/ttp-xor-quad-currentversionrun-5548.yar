rule TTP_XOR_QUAD_CurrentVersionRun_5548 {
  strings:
    $key_5548 = { 06 27 [2] 22 29 [2] 09 05 [2] 27 27 [2] 33 3c [2] 3c 26 [2] 22 3b [2] 20 3a [2] 3b 3c [2] 27 3b [2] 3b 14 }

  condition:
    any of them
}