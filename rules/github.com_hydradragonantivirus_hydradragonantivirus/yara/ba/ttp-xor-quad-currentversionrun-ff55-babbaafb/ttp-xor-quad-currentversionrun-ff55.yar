rule TTP_XOR_QUAD_CurrentVersionRun_ff55 {
  strings:
    $key_ff55 = { ac 3a [2] 88 34 [2] a3 18 [2] 8d 3a [2] 99 21 [2] 96 3b [2] 88 26 [2] 8a 27 [2] 91 21 [2] 8d 26 [2] 91 09 }

  condition:
    any of them
}