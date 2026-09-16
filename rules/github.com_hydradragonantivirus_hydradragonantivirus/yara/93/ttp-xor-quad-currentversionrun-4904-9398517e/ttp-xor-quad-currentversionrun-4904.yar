rule TTP_XOR_QUAD_CurrentVersionRun_4904 {
  strings:
    $key_4904 = { 1a 6b [2] 3e 65 [2] 15 49 [2] 3b 6b [2] 2f 70 [2] 20 6a [2] 3e 77 [2] 3c 76 [2] 27 70 [2] 3b 77 [2] 27 58 }

  condition:
    any of them
}