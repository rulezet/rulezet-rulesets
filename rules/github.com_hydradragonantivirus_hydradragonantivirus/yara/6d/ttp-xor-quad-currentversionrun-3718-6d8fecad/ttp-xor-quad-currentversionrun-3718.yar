rule TTP_XOR_QUAD_CurrentVersionRun_3718 {
  strings:
    $key_3718 = { 64 77 [2] 40 79 [2] 6b 55 [2] 45 77 [2] 51 6c [2] 5e 76 [2] 40 6b [2] 42 6a [2] 59 6c [2] 45 6b [2] 59 44 }

  condition:
    any of them
}