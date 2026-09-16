rule TTP_XOR_QUAD_CurrentVersionRun_6f78 {
  strings:
    $key_6f78 = { 3c 17 [2] 18 19 [2] 33 35 [2] 1d 17 [2] 09 0c [2] 06 16 [2] 18 0b [2] 1a 0a [2] 01 0c [2] 1d 0b [2] 01 24 }

  condition:
    any of them
}