rule TTP_XOR_QUAD_CurrentVersionRun_1c6b {
  strings:
    $key_1c6b = { 4f 04 [2] 6b 0a [2] 40 26 [2] 6e 04 [2] 7a 1f [2] 75 05 [2] 6b 18 [2] 69 19 [2] 72 1f [2] 6e 18 [2] 72 37 }

  condition:
    any of them
}