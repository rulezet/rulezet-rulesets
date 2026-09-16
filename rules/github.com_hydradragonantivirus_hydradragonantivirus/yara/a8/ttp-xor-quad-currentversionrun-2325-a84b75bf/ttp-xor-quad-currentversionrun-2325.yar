rule TTP_XOR_QUAD_CurrentVersionRun_2325 {
  strings:
    $key_2325 = { 70 4a [2] 54 44 [2] 7f 68 [2] 51 4a [2] 45 51 [2] 4a 4b [2] 54 56 [2] 56 57 [2] 4d 51 [2] 51 56 [2] 4d 79 }

  condition:
    any of them
}