rule TTP_XOR_QUAD_CurrentVersionRun_5a17 {
  strings:
    $key_5a17 = { 09 78 [2] 2d 76 [2] 06 5a [2] 28 78 [2] 3c 63 [2] 33 79 [2] 2d 64 [2] 2f 65 [2] 34 63 [2] 28 64 [2] 34 4b }

  condition:
    any of them
}