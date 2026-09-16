rule TTP_XOR_QUAD_CurrentVersionRun_524b {
  strings:
    $key_524b = { 01 24 [2] 25 2a [2] 0e 06 [2] 20 24 [2] 34 3f [2] 3b 25 [2] 25 38 [2] 27 39 [2] 3c 3f [2] 20 38 [2] 3c 17 }

  condition:
    any of them
}