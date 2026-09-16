rule TTP_XOR_QUAD_CurrentVersionRun_4144 {
  strings:
    $key_4144 = { 12 2b [2] 36 25 [2] 1d 09 [2] 33 2b [2] 27 30 [2] 28 2a [2] 36 37 [2] 34 36 [2] 2f 30 [2] 33 37 [2] 2f 18 }

  condition:
    any of them
}