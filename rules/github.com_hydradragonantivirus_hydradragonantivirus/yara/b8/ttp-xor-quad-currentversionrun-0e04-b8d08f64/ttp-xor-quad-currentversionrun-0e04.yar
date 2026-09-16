rule TTP_XOR_QUAD_CurrentVersionRun_0e04 {
  strings:
    $key_0e04 = { 5d 6b [2] 79 65 [2] 52 49 [2] 7c 6b [2] 68 70 [2] 67 6a [2] 79 77 [2] 7b 76 [2] 60 70 [2] 7c 77 [2] 60 58 }

  condition:
    any of them
}