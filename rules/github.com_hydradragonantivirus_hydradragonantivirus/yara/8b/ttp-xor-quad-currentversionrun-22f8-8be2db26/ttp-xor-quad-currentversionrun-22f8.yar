rule TTP_XOR_QUAD_CurrentVersionRun_22f8 {
  strings:
    $key_22f8 = { 71 97 [2] 55 99 [2] 7e b5 [2] 50 97 [2] 44 8c [2] 4b 96 [2] 55 8b [2] 57 8a [2] 4c 8c [2] 50 8b [2] 4c a4 }

  condition:
    any of them
}