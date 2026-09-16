rule TTP_XOR_QUAD_CurrentVersionRun_5718 {
  strings:
    $key_5718 = { 04 77 [2] 20 79 [2] 0b 55 [2] 25 77 [2] 31 6c [2] 3e 76 [2] 20 6b [2] 22 6a [2] 39 6c [2] 25 6b [2] 39 44 }

  condition:
    any of them
}