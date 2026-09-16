rule TTP_XOR_QUAD_CurrentVersionRun_256b {
  strings:
    $key_256b = { 76 04 [2] 52 0a [2] 79 26 [2] 57 04 [2] 43 1f [2] 4c 05 [2] 52 18 [2] 50 19 [2] 4b 1f [2] 57 18 [2] 4b 37 }

  condition:
    any of them
}