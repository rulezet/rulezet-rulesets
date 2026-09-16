rule TTP_XOR_QUAD_CurrentVersionRun_f424 {
  strings:
    $key_f424 = { a7 4b [2] 83 45 [2] a8 69 [2] 86 4b [2] 92 50 [2] 9d 4a [2] 83 57 [2] 81 56 [2] 9a 50 [2] 86 57 [2] 9a 78 }

  condition:
    any of them
}