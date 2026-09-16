rule TTP_XOR_QUAD_CurrentVersionRun_3617 {
  strings:
    $key_3617 = { 65 78 [2] 41 76 [2] 6a 5a [2] 44 78 [2] 50 63 [2] 5f 79 [2] 41 64 [2] 43 65 [2] 58 63 [2] 44 64 [2] 58 4b }

  condition:
    any of them
}