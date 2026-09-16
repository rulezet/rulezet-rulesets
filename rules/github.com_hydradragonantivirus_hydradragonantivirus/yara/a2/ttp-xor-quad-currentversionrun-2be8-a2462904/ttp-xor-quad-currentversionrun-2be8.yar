rule TTP_XOR_QUAD_CurrentVersionRun_2be8 {
  strings:
    $key_2be8 = { 78 87 [2] 5c 89 [2] 77 a5 [2] 59 87 [2] 4d 9c [2] 42 86 [2] 5c 9b [2] 5e 9a [2] 45 9c [2] 59 9b [2] 45 b4 }

  condition:
    any of them
}