rule TTP_XOR_QUAD_CurrentVersionRun_05e8 {
  strings:
    $key_05e8 = { 56 87 [2] 72 89 [2] 59 a5 [2] 77 87 [2] 63 9c [2] 6c 86 [2] 72 9b [2] 70 9a [2] 6b 9c [2] 77 9b [2] 6b b4 }

  condition:
    any of them
}