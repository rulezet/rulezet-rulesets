rule TTP_XOR_QUAD_CurrentVersionRun_3317 {
  strings:
    $key_3317 = { 60 78 [2] 44 76 [2] 6f 5a [2] 41 78 [2] 55 63 [2] 5a 79 [2] 44 64 [2] 46 65 [2] 5d 63 [2] 41 64 [2] 5d 4b }

  condition:
    any of them
}