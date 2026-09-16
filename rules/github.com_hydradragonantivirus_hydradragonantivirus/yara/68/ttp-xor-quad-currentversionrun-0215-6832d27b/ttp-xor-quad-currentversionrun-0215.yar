rule TTP_XOR_QUAD_CurrentVersionRun_0215 {
  strings:
    $key_0215 = { 51 7a [2] 75 74 [2] 5e 58 [2] 70 7a [2] 64 61 [2] 6b 7b [2] 75 66 [2] 77 67 [2] 6c 61 [2] 70 66 [2] 6c 49 }

  condition:
    any of them
}