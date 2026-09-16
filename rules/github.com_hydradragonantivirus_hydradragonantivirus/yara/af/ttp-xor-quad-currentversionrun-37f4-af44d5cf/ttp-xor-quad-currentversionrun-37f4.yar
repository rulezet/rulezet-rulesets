rule TTP_XOR_QUAD_CurrentVersionRun_37f4 {
  strings:
    $key_37f4 = { 64 9b [2] 40 95 [2] 6b b9 [2] 45 9b [2] 51 80 [2] 5e 9a [2] 40 87 [2] 42 86 [2] 59 80 [2] 45 87 [2] 59 a8 }

  condition:
    any of them
}