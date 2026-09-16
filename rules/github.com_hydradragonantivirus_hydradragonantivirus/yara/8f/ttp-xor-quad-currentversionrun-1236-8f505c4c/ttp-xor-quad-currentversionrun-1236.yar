rule TTP_XOR_QUAD_CurrentVersionRun_1236 {
  strings:
    $key_1236 = { 41 59 [2] 65 57 [2] 4e 7b [2] 60 59 [2] 74 42 [2] 7b 58 [2] 65 45 [2] 67 44 [2] 7c 42 [2] 60 45 [2] 7c 6a }

  condition:
    any of them
}