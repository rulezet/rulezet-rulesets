rule TTP_XOR_QUAD_CurrentVersionRun_4c04 {
  strings:
    $key_4c04 = { 1f 6b [2] 3b 65 [2] 10 49 [2] 3e 6b [2] 2a 70 [2] 25 6a [2] 3b 77 [2] 39 76 [2] 22 70 [2] 3e 77 [2] 22 58 }

  condition:
    any of them
}