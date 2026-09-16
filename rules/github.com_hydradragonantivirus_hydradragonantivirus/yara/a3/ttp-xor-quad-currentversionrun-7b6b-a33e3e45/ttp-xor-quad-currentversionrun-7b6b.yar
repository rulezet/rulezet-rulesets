rule TTP_XOR_QUAD_CurrentVersionRun_7b6b {
  strings:
    $key_7b6b = { 28 04 [2] 0c 0a [2] 27 26 [2] 09 04 [2] 1d 1f [2] 12 05 [2] 0c 18 [2] 0e 19 [2] 15 1f [2] 09 18 [2] 15 37 }

  condition:
    any of them
}