rule TTP_XOR_QUAD_CurrentVersionRun_2a17 {
  strings:
    $key_2a17 = { 79 78 [2] 5d 76 [2] 76 5a [2] 58 78 [2] 4c 63 [2] 43 79 [2] 5d 64 [2] 5f 65 [2] 44 63 [2] 58 64 [2] 44 4b }

  condition:
    any of them
}