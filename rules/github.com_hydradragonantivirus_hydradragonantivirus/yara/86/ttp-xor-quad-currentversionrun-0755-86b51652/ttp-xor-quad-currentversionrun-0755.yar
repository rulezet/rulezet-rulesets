rule TTP_XOR_QUAD_CurrentVersionRun_0755 {
  strings:
    $key_0755 = { 54 3a [2] 70 34 [2] 5b 18 [2] 75 3a [2] 61 21 [2] 6e 3b [2] 70 26 [2] 72 27 [2] 69 21 [2] 75 26 [2] 69 09 }

  condition:
    any of them
}