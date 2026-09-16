rule TTP_XOR_QUAD_CurrentVersionRun_354b {
  strings:
    $key_354b = { 66 24 [2] 42 2a [2] 69 06 [2] 47 24 [2] 53 3f [2] 5c 25 [2] 42 38 [2] 40 39 [2] 5b 3f [2] 47 38 [2] 5b 17 }

  condition:
    any of them
}