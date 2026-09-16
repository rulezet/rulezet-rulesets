rule TTP_XOR_QUAD_CurrentVersionRun_6544 {
  strings:
    $key_6544 = { 36 2b [2] 12 25 [2] 39 09 [2] 17 2b [2] 03 30 [2] 0c 2a [2] 12 37 [2] 10 36 [2] 0b 30 [2] 17 37 [2] 0b 18 }

  condition:
    any of them
}