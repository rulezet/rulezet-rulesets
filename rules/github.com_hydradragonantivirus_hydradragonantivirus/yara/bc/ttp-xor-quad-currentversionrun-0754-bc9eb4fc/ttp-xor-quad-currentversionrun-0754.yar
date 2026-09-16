rule TTP_XOR_QUAD_CurrentVersionRun_0754 {
  strings:
    $key_0754 = { 54 3b [2] 70 35 [2] 5b 19 [2] 75 3b [2] 61 20 [2] 6e 3a [2] 70 27 [2] 72 26 [2] 69 20 [2] 75 27 [2] 69 08 }

  condition:
    any of them
}