rule TTP_XOR_QUAD_CurrentVersionRun_f14b {
  strings:
    $key_f14b = { a2 24 [2] 86 2a [2] ad 06 [2] 83 24 [2] 97 3f [2] 98 25 [2] 86 38 [2] 84 39 [2] 9f 3f [2] 83 38 [2] 9f 17 }

  condition:
    any of them
}