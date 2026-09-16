rule TTP_XOR_QUAD_CurrentVersionRun_2525 {
  strings:
    $key_2525 = { 76 4a [2] 52 44 [2] 79 68 [2] 57 4a [2] 43 51 [2] 4c 4b [2] 52 56 [2] 50 57 [2] 4b 51 [2] 57 56 [2] 4b 79 }

  condition:
    any of them
}