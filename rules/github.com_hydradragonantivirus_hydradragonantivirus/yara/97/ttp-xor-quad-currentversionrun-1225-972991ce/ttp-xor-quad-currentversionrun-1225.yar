rule TTP_XOR_QUAD_CurrentVersionRun_1225 {
  strings:
    $key_1225 = { 41 4a [2] 65 44 [2] 4e 68 [2] 60 4a [2] 74 51 [2] 7b 4b [2] 65 56 [2] 67 57 [2] 7c 51 [2] 60 56 [2] 7c 79 }

  condition:
    any of them
}