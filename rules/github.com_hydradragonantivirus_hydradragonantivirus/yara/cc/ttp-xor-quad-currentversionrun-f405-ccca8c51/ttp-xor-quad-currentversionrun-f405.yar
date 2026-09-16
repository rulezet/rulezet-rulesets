rule TTP_XOR_QUAD_CurrentVersionRun_f405 {
  strings:
    $key_f405 = { a7 6a [2] 83 64 [2] a8 48 [2] 86 6a [2] 92 71 [2] 9d 6b [2] 83 76 [2] 81 77 [2] 9a 71 [2] 86 76 [2] 9a 59 }

  condition:
    any of them
}