rule TTP_XOR_QUAD_CurrentVersionRun_6c6b {
  strings:
    $key_6c6b = { 3f 04 [2] 1b 0a [2] 30 26 [2] 1e 04 [2] 0a 1f [2] 05 05 [2] 1b 18 [2] 19 19 [2] 02 1f [2] 1e 18 [2] 02 37 }

  condition:
    any of them
}