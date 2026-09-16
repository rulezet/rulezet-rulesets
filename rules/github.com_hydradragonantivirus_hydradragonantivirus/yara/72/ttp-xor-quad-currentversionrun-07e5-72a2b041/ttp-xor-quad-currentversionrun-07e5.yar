rule TTP_XOR_QUAD_CurrentVersionRun_07e5 {
  strings:
    $key_07e5 = { 54 8a [2] 70 84 [2] 5b a8 [2] 75 8a [2] 61 91 [2] 6e 8b [2] 70 96 [2] 72 97 [2] 69 91 [2] 75 96 [2] 69 b9 }

  condition:
    any of them
}