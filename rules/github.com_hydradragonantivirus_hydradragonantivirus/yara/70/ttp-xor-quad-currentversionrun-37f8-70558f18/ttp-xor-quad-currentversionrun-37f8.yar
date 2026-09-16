rule TTP_XOR_QUAD_CurrentVersionRun_37f8 {
  strings:
    $key_37f8 = { 64 97 [2] 40 99 [2] 6b b5 [2] 45 97 [2] 51 8c [2] 5e 96 [2] 40 8b [2] 42 8a [2] 59 8c [2] 45 8b [2] 59 a4 }

  condition:
    any of them
}