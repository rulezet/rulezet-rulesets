rule TTP_XOR_QUAD_CurrentVersionRun_4d6b {
  strings:
    $key_4d6b = { 1e 04 [2] 3a 0a [2] 11 26 [2] 3f 04 [2] 2b 1f [2] 24 05 [2] 3a 18 [2] 38 19 [2] 23 1f [2] 3f 18 [2] 23 37 }

  condition:
    any of them
}