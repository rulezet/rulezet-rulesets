rule TTP_XOR_QUAD_CurrentVersionRun_004b {
  strings:
    $key_004b = { 53 24 [2] 77 2a [2] 5c 06 [2] 72 24 [2] 66 3f [2] 69 25 [2] 77 38 [2] 75 39 [2] 6e 3f [2] 72 38 [2] 6e 17 }

  condition:
    any of them
}