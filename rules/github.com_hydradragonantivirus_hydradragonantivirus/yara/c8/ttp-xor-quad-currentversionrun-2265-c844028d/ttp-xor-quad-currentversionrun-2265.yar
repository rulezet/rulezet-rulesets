rule TTP_XOR_QUAD_CurrentVersionRun_2265 {
  strings:
    $key_2265 = { 71 0a [2] 55 04 [2] 7e 28 [2] 50 0a [2] 44 11 [2] 4b 0b [2] 55 16 [2] 57 17 [2] 4c 11 [2] 50 16 [2] 4c 39 }

  condition:
    any of them
}