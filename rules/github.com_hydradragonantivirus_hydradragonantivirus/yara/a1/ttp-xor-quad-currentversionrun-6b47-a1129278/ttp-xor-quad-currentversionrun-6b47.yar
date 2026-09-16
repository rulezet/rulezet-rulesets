rule TTP_XOR_QUAD_CurrentVersionRun_6b47 {
  strings:
    $key_6b47 = { 38 28 [2] 1c 26 [2] 37 0a [2] 19 28 [2] 0d 33 [2] 02 29 [2] 1c 34 [2] 1e 35 [2] 05 33 [2] 19 34 [2] 05 1b }

  condition:
    any of them
}