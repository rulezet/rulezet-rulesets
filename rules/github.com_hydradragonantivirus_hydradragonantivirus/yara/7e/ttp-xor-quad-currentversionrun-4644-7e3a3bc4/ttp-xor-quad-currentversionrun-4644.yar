rule TTP_XOR_QUAD_CurrentVersionRun_4644 {
  strings:
    $key_4644 = { 15 2b [2] 31 25 [2] 1a 09 [2] 34 2b [2] 20 30 [2] 2f 2a [2] 31 37 [2] 33 36 [2] 28 30 [2] 34 37 [2] 28 18 }

  condition:
    any of them
}