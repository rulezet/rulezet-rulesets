rule TTP_XOR_QUAD_CurrentVersionRun_1c44 {
  strings:
    $key_1c44 = { 4f 2b [2] 6b 25 [2] 40 09 [2] 6e 2b [2] 7a 30 [2] 75 2a [2] 6b 37 [2] 69 36 [2] 72 30 [2] 6e 37 [2] 72 18 }

  condition:
    any of them
}