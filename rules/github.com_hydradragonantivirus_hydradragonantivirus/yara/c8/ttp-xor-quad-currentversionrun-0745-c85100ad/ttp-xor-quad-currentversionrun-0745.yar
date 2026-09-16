rule TTP_XOR_QUAD_CurrentVersionRun_0745 {
  strings:
    $key_0745 = { 54 2a [2] 70 24 [2] 5b 08 [2] 75 2a [2] 61 31 [2] 6e 2b [2] 70 36 [2] 72 37 [2] 69 31 [2] 75 36 [2] 69 19 }

  condition:
    any of them
}