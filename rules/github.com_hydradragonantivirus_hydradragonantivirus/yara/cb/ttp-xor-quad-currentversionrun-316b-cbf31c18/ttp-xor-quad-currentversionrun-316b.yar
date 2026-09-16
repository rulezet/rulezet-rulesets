rule TTP_XOR_QUAD_CurrentVersionRun_316b {
  strings:
    $key_316b = { 62 04 [2] 46 0a [2] 6d 26 [2] 43 04 [2] 57 1f [2] 58 05 [2] 46 18 [2] 44 19 [2] 5f 1f [2] 43 18 [2] 5f 37 }

  condition:
    any of them
}