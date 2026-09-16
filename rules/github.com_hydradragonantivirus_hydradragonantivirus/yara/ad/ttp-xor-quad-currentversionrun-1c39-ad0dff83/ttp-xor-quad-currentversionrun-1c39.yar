rule TTP_XOR_QUAD_CurrentVersionRun_1c39 {
  strings:
    $key_1c39 = { 4f 56 [2] 6b 58 [2] 40 74 [2] 6e 56 [2] 7a 4d [2] 75 57 [2] 6b 4a [2] 69 4b [2] 72 4d [2] 6e 4a [2] 72 65 }

  condition:
    any of them
}