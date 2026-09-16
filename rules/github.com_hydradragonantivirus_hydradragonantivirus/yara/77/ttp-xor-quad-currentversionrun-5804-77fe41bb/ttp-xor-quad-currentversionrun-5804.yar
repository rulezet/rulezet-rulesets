rule TTP_XOR_QUAD_CurrentVersionRun_5804 {
  strings:
    $key_5804 = { 0b 6b [2] 2f 65 [2] 04 49 [2] 2a 6b [2] 3e 70 [2] 31 6a [2] 2f 77 [2] 2d 76 [2] 36 70 [2] 2a 77 [2] 36 58 }

  condition:
    any of them
}