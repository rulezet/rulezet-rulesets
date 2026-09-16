rule TTP_XOR_QUAD_CurrentVersionRun_3e15 {
  strings:
    $key_3e15 = { 6d 7a [2] 49 74 [2] 62 58 [2] 4c 7a [2] 58 61 [2] 57 7b [2] 49 66 [2] 4b 67 [2] 50 61 [2] 4c 66 [2] 50 49 }

  condition:
    any of them
}