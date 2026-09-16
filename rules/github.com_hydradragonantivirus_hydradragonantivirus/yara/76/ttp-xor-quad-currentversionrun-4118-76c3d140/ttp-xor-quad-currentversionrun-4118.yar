rule TTP_XOR_QUAD_CurrentVersionRun_4118 {
  strings:
    $key_4118 = { 12 77 [2] 36 79 [2] 1d 55 [2] 33 77 [2] 27 6c [2] 28 76 [2] 36 6b [2] 34 6a [2] 2f 6c [2] 33 6b [2] 2f 44 }

  condition:
    any of them
}