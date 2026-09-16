rule TTP_XOR_QUAD_CurrentVersionRun_006b {
  strings:
    $key_006b = { 53 04 [2] 77 0a [2] 5c 26 [2] 72 04 [2] 66 1f [2] 69 05 [2] 77 18 [2] 75 19 [2] 6e 1f [2] 72 18 [2] 6e 37 }

  condition:
    any of them
}