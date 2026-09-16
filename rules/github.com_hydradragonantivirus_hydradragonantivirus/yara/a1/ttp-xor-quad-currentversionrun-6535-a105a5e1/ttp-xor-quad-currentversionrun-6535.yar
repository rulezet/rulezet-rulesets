rule TTP_XOR_QUAD_CurrentVersionRun_6535 {
  strings:
    $key_6535 = { 36 5a [2] 12 54 [2] 39 78 [2] 17 5a [2] 03 41 [2] 0c 5b [2] 12 46 [2] 10 47 [2] 0b 41 [2] 17 46 [2] 0b 69 }

  condition:
    any of them
}