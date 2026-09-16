rule TTP_XOR_QUAD_CurrentVersionRun_0847 {
  strings:
    $key_0847 = { 5b 28 [2] 7f 26 [2] 54 0a [2] 7a 28 [2] 6e 33 [2] 61 29 [2] 7f 34 [2] 7d 35 [2] 66 33 [2] 7a 34 [2] 66 1b }

  condition:
    any of them
}