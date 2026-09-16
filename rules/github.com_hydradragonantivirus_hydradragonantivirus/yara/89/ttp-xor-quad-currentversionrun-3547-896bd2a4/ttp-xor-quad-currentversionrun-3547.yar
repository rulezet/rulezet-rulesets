rule TTP_XOR_QUAD_CurrentVersionRun_3547 {
  strings:
    $key_3547 = { 66 28 [2] 42 26 [2] 69 0a [2] 47 28 [2] 53 33 [2] 5c 29 [2] 42 34 [2] 40 35 [2] 5b 33 [2] 47 34 [2] 5b 1b }

  condition:
    any of them
}