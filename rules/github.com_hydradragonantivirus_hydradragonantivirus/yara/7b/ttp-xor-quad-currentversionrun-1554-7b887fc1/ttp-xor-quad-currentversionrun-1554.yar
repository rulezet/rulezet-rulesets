rule TTP_XOR_QUAD_CurrentVersionRun_1554 {
  strings:
    $key_1554 = { 46 3b [2] 62 35 [2] 49 19 [2] 67 3b [2] 73 20 [2] 7c 3a [2] 62 27 [2] 60 26 [2] 7b 20 [2] 67 27 [2] 7b 08 }

  condition:
    any of them
}