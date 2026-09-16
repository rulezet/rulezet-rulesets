rule TTP_XOR_QUAD_CurrentVersionRun_076b {
  strings:
    $key_076b = { 54 04 [2] 70 0a [2] 5b 26 [2] 75 04 [2] 61 1f [2] 6e 05 [2] 70 18 [2] 72 19 [2] 69 1f [2] 75 18 [2] 69 37 }

  condition:
    any of them
}