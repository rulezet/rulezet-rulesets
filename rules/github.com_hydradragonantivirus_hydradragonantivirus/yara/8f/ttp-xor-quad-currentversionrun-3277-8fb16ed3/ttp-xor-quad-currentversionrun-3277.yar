rule TTP_XOR_QUAD_CurrentVersionRun_3277 {
  strings:
    $key_3277 = { 61 18 [2] 45 16 [2] 6e 3a [2] 40 18 [2] 54 03 [2] 5b 19 [2] 45 04 [2] 47 05 [2] 5c 03 [2] 40 04 [2] 5c 2b }

  condition:
    any of them
}