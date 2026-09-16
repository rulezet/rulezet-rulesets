rule TTP_XOR_QUAD_CurrentVersionRun_5117 {
  strings:
    $key_5117 = { 02 78 [2] 26 76 [2] 0d 5a [2] 23 78 [2] 37 63 [2] 38 79 [2] 26 64 [2] 24 65 [2] 3f 63 [2] 23 64 [2] 3f 4b }

  condition:
    any of them
}