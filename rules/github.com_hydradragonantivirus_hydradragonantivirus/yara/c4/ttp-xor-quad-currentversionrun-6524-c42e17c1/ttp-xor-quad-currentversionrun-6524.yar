rule TTP_XOR_QUAD_CurrentVersionRun_6524 {
  strings:
    $key_6524 = { 36 4b [2] 12 45 [2] 39 69 [2] 17 4b [2] 03 50 [2] 0c 4a [2] 12 57 [2] 10 56 [2] 0b 50 [2] 17 57 [2] 0b 78 }

  condition:
    any of them
}