rule TTP_XOR_QUAD_CurrentVersionRun_084b {
  strings:
    $key_084b = { 5b 24 [2] 7f 2a [2] 54 06 [2] 7a 24 [2] 6e 3f [2] 61 25 [2] 7f 38 [2] 7d 39 [2] 66 3f [2] 7a 38 [2] 66 17 }

  condition:
    any of them
}