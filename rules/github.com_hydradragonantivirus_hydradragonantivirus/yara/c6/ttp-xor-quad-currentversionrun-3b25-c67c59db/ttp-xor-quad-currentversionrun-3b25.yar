rule TTP_XOR_QUAD_CurrentVersionRun_3b25 {
  strings:
    $key_3b25 = { 68 4a [2] 4c 44 [2] 67 68 [2] 49 4a [2] 5d 51 [2] 52 4b [2] 4c 56 [2] 4e 57 [2] 55 51 [2] 49 56 [2] 55 79 }

  condition:
    any of them
}