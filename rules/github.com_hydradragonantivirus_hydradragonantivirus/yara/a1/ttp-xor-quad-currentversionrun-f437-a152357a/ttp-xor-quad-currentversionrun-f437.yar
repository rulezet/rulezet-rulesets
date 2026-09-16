rule TTP_XOR_QUAD_CurrentVersionRun_f437 {
  strings:
    $key_f437 = { a7 58 [2] 83 56 [2] a8 7a [2] 86 58 [2] 92 43 [2] 9d 59 [2] 83 44 [2] 81 45 [2] 9a 43 [2] 86 44 [2] 9a 6b }

  condition:
    any of them
}