rule TTP_XOR_QUAD_CurrentVersionRun_30e8 {
  strings:
    $key_30e8 = { 63 87 [2] 47 89 [2] 6c a5 [2] 42 87 [2] 56 9c [2] 59 86 [2] 47 9b [2] 45 9a [2] 5e 9c [2] 42 9b [2] 5e b4 }

  condition:
    any of them
}