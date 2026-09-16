rule TTP_XOR_QUAD_CurrentVersionRun_f74b {
  strings:
    $key_f74b = { a4 24 [2] 80 2a [2] ab 06 [2] 85 24 [2] 91 3f [2] 9e 25 [2] 80 38 [2] 82 39 [2] 99 3f [2] 85 38 [2] 99 17 }

  condition:
    any of them
}