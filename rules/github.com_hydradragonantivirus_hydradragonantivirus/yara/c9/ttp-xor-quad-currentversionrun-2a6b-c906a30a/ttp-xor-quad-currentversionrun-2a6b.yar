rule TTP_XOR_QUAD_CurrentVersionRun_2a6b {
  strings:
    $key_2a6b = { 79 04 [2] 5d 0a [2] 76 26 [2] 58 04 [2] 4c 1f [2] 43 05 [2] 5d 18 [2] 5f 19 [2] 44 1f [2] 58 18 [2] 44 37 }

  condition:
    any of them
}