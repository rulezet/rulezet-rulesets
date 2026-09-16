rule TTP_XOR_QUAD_CurrentVersionRun_1ce5 {
  strings:
    $key_1ce5 = { 4f 8a [2] 6b 84 [2] 40 a8 [2] 6e 8a [2] 7a 91 [2] 75 8b [2] 6b 96 [2] 69 97 [2] 72 91 [2] 6e 96 [2] 72 b9 }

  condition:
    any of them
}