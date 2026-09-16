rule TTP_XOR_QUAD_CurrentVersionRun_f465 {
  strings:
    $key_f465 = { a7 0a [2] 83 04 [2] a8 28 [2] 86 0a [2] 92 11 [2] 9d 0b [2] 83 16 [2] 81 17 [2] 9a 11 [2] 86 16 [2] 9a 39 }

  condition:
    any of them
}