rule TTP_XOR_QUAD_CurrentVersionRun_f348 {
  strings:
    $key_f348 = { a0 27 [2] 84 29 [2] af 05 [2] 81 27 [2] 95 3c [2] 9a 26 [2] 84 3b [2] 86 3a [2] 9d 3c [2] 81 3b [2] 9d 14 }

  condition:
    any of them
}