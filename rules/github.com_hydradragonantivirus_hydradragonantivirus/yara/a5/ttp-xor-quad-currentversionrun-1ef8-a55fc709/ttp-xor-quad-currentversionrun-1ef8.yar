rule TTP_XOR_QUAD_CurrentVersionRun_1ef8 {
  strings:
    $key_1ef8 = { 4d 97 [2] 69 99 [2] 42 b5 [2] 6c 97 [2] 78 8c [2] 77 96 [2] 69 8b [2] 6b 8a [2] 70 8c [2] 6c 8b [2] 70 a4 }

  condition:
    any of them
}