rule TTP_XOR_QUAD_CurrentVersionRun_6d25 {
  strings:
    $key_6d25 = { 3e 4a [2] 1a 44 [2] 31 68 [2] 1f 4a [2] 0b 51 [2] 04 4b [2] 1a 56 [2] 18 57 [2] 03 51 [2] 1f 56 [2] 03 79 }

  condition:
    any of them
}