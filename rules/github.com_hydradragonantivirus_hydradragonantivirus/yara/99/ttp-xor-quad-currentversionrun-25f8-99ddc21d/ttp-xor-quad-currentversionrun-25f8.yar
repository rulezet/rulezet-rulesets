rule TTP_XOR_QUAD_CurrentVersionRun_25f8 {
  strings:
    $key_25f8 = { 76 97 [2] 52 99 [2] 79 b5 [2] 57 97 [2] 43 8c [2] 4c 96 [2] 52 8b [2] 50 8a [2] 4b 8c [2] 57 8b [2] 4b a4 }

  condition:
    any of them
}