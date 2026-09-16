rule TTP_XOR_QUAD_CurrentVersionRun_5554 {
  strings:
    $key_5554 = { 06 3b [2] 22 35 [2] 09 19 [2] 27 3b [2] 33 20 [2] 3c 3a [2] 22 27 [2] 20 26 [2] 3b 20 [2] 27 27 [2] 3b 08 }

  condition:
    any of them
}