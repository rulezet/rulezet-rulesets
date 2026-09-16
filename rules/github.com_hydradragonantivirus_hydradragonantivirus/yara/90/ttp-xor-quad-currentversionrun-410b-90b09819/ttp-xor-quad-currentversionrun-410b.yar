rule TTP_XOR_QUAD_CurrentVersionRun_410b {
  strings:
    $key_410b = { 12 64 [2] 36 6a [2] 1d 46 [2] 33 64 [2] 27 7f [2] 28 65 [2] 36 78 [2] 34 79 [2] 2f 7f [2] 33 78 [2] 2f 57 }

  condition:
    any of them
}