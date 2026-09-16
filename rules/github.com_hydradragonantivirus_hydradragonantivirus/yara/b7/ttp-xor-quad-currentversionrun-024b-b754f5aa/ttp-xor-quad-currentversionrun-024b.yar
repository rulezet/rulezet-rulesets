rule TTP_XOR_QUAD_CurrentVersionRun_024b {
  strings:
    $key_024b = { 51 24 [2] 75 2a [2] 5e 06 [2] 70 24 [2] 64 3f [2] 6b 25 [2] 75 38 [2] 77 39 [2] 6c 3f [2] 70 38 [2] 6c 17 }

  condition:
    any of them
}