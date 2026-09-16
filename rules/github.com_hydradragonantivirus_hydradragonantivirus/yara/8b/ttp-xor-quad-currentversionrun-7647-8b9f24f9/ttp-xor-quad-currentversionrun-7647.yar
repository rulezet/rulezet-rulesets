rule TTP_XOR_QUAD_CurrentVersionRun_7647 {
  strings:
    $key_7647 = { 25 28 [2] 01 26 [2] 2a 0a [2] 04 28 [2] 10 33 [2] 1f 29 [2] 01 34 [2] 03 35 [2] 18 33 [2] 04 34 [2] 18 1b }

  condition:
    any of them
}