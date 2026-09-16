rule TTP_XOR_QUAD_CurrentVersionRun_f56b {
  strings:
    $key_f56b = { a6 04 [2] 82 0a [2] a9 26 [2] 87 04 [2] 93 1f [2] 9c 05 [2] 82 18 [2] 80 19 [2] 9b 1f [2] 87 18 [2] 9b 37 }

  condition:
    any of them
}