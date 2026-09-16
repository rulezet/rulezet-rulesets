rule TTP_XOR_QUAD_CurrentVersionRun_0004 {
  strings:
    $key_0004 = { 53 6b [2] 77 65 [2] 5c 49 [2] 72 6b [2] 66 70 [2] 69 6a [2] 77 77 [2] 75 76 [2] 6e 70 [2] 72 77 [2] 6e 58 }

  condition:
    any of them
}