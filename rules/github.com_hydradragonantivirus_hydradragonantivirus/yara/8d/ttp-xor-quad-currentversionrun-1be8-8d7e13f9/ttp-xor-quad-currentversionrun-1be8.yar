rule TTP_XOR_QUAD_CurrentVersionRun_1be8 {
  strings:
    $key_1be8 = { 48 87 [2] 6c 89 [2] 47 a5 [2] 69 87 [2] 7d 9c [2] 72 86 [2] 6c 9b [2] 6e 9a [2] 75 9c [2] 69 9b [2] 75 b4 }

  condition:
    any of them
}