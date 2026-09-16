rule TTP_XOR_QUAD_CurrentVersionRun_6317 {
  strings:
    $key_6317 = { 30 78 [2] 14 76 [2] 3f 5a [2] 11 78 [2] 05 63 [2] 0a 79 [2] 14 64 [2] 16 65 [2] 0d 63 [2] 11 64 [2] 0d 4b }

  condition:
    any of them
}