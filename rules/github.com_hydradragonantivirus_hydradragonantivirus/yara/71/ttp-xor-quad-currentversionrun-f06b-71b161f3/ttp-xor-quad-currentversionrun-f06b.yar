rule TTP_XOR_QUAD_CurrentVersionRun_f06b {
  strings:
    $key_f06b = { a3 04 [2] 87 0a [2] ac 26 [2] 82 04 [2] 96 1f [2] 99 05 [2] 87 18 [2] 85 19 [2] 9e 1f [2] 82 18 [2] 9e 37 }

  condition:
    any of them
}