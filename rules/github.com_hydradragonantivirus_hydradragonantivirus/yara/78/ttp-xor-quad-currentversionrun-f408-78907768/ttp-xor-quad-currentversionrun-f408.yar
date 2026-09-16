rule TTP_XOR_QUAD_CurrentVersionRun_f408 {
  strings:
    $key_f408 = { a7 67 [2] 83 69 [2] a8 45 [2] 86 67 [2] 92 7c [2] 9d 66 [2] 83 7b [2] 81 7a [2] 9a 7c [2] 86 7b [2] 9a 54 }

  condition:
    any of them
}