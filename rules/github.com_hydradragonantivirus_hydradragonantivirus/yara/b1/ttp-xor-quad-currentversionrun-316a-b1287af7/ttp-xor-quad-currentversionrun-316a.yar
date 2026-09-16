rule TTP_XOR_QUAD_CurrentVersionRun_316a {
  strings:
    $key_316a = { 62 05 [2] 46 0b [2] 6d 27 [2] 43 05 [2] 57 1e [2] 58 04 [2] 46 19 [2] 44 18 [2] 5f 1e [2] 43 19 [2] 5f 36 }

  condition:
    any of them
}