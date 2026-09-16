rule TTP_XOR_QUAD_CurrentVersionRun_1036 {
  strings:
    $key_1036 = { 43 59 [2] 67 57 [2] 4c 7b [2] 62 59 [2] 76 42 [2] 79 58 [2] 67 45 [2] 65 44 [2] 7e 42 [2] 62 45 [2] 7e 6a }

  condition:
    any of them
}