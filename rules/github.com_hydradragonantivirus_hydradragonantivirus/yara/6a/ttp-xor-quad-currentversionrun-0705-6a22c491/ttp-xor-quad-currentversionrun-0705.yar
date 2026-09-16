rule TTP_XOR_QUAD_CurrentVersionRun_0705 {
  strings:
    $key_0705 = { 54 6a [2] 70 64 [2] 5b 48 [2] 75 6a [2] 61 71 [2] 6e 6b [2] 70 76 [2] 72 77 [2] 69 71 [2] 75 76 [2] 69 59 }

  condition:
    any of them
}