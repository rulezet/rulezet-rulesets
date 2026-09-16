rule TTP_XOR_QUAD_CurrentVersionRun_1e15 {
  strings:
    $key_1e15 = { 4d 7a [2] 69 74 [2] 42 58 [2] 6c 7a [2] 78 61 [2] 77 7b [2] 69 66 [2] 6b 67 [2] 70 61 [2] 6c 66 [2] 70 49 }

  condition:
    any of them
}