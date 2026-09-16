rule TTP_XOR_QUAD_CurrentVersionRun_0c04 {
  strings:
    $key_0c04 = { 5f 6b [2] 7b 65 [2] 50 49 [2] 7e 6b [2] 6a 70 [2] 65 6a [2] 7b 77 [2] 79 76 [2] 62 70 [2] 7e 77 [2] 62 58 }

  condition:
    any of them
}