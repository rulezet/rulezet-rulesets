rule TTP_XOR_QUAD_CurrentVersionRun_766b {
  strings:
    $key_766b = { 25 04 [2] 01 0a [2] 2a 26 [2] 04 04 [2] 10 1f [2] 1f 05 [2] 01 18 [2] 03 19 [2] 18 1f [2] 04 18 [2] 18 37 }

  condition:
    any of them
}