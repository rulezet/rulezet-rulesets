rule TTP_XOR_QUAD_CurrentVersionRun_6518 {
  strings:
    $key_6518 = { 36 77 [2] 12 79 [2] 39 55 [2] 17 77 [2] 03 6c [2] 0c 76 [2] 12 6b [2] 10 6a [2] 0b 6c [2] 17 6b [2] 0b 44 }

  condition:
    any of them
}