rule TTP_XOR_QUAD_CurrentVersionRun_0704 {
  strings:
    $key_0704 = { 54 6b [2] 70 65 [2] 5b 49 [2] 75 6b [2] 61 70 [2] 6e 6a [2] 70 77 [2] 72 76 [2] 69 70 [2] 75 77 [2] 69 58 }

  condition:
    any of them
}