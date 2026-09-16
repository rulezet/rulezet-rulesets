rule TTP_XOR_QUAD_CurrentVersionRun_5171 {
  strings:
    $key_5171 = { 02 1e [2] 26 10 [2] 0d 3c [2] 23 1e [2] 37 05 [2] 38 1f [2] 26 02 [2] 24 03 [2] 3f 05 [2] 23 02 [2] 3f 2d }

  condition:
    any of them
}