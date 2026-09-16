rule TTP_XOR_QUAD_CurrentVersionRun_7656 {
  strings:
    $key_7656 = { 25 39 [2] 01 37 [2] 2a 1b [2] 04 39 [2] 10 22 [2] 1f 38 [2] 01 25 [2] 03 24 [2] 18 22 [2] 04 25 [2] 18 0a }

  condition:
    any of them
}