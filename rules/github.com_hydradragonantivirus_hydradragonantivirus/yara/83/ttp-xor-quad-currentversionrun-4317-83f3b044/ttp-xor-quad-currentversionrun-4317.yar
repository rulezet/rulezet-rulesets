rule TTP_XOR_QUAD_CurrentVersionRun_4317 {
  strings:
    $key_4317 = { 10 78 [2] 34 76 [2] 1f 5a [2] 31 78 [2] 25 63 [2] 2a 79 [2] 34 64 [2] 36 65 [2] 2d 63 [2] 31 64 [2] 2d 4b }

  condition:
    any of them
}