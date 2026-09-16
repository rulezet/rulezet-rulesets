rule TTP_XOR_QUAD_CurrentVersionRun_4647 {
  strings:
    $key_4647 = { 15 28 [2] 31 26 [2] 1a 0a [2] 34 28 [2] 20 33 [2] 2f 29 [2] 31 34 [2] 33 35 [2] 28 33 [2] 34 34 [2] 28 1b }

  condition:
    any of them
}