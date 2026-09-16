rule TTP_XOR_QUAD_CurrentVersionRun_19e8 {
  strings:
    $key_19e8 = { 4a 87 [2] 6e 89 [2] 45 a5 [2] 6b 87 [2] 7f 9c [2] 70 86 [2] 6e 9b [2] 6c 9a [2] 77 9c [2] 6b 9b [2] 77 b4 }

  condition:
    any of them
}