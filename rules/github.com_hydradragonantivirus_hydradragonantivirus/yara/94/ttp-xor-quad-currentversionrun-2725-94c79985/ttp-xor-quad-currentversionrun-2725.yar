rule TTP_XOR_QUAD_CurrentVersionRun_2725 {
  strings:
    $key_2725 = { 74 4a [2] 50 44 [2] 7b 68 [2] 55 4a [2] 41 51 [2] 4e 4b [2] 50 56 [2] 52 57 [2] 49 51 [2] 55 56 [2] 49 79 }

  condition:
    any of them
}