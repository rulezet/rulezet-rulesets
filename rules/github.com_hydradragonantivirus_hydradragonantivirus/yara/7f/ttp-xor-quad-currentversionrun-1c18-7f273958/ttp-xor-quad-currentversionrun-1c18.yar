rule TTP_XOR_QUAD_CurrentVersionRun_1c18 {
  strings:
    $key_1c18 = { 4f 77 [2] 6b 79 [2] 40 55 [2] 6e 77 [2] 7a 6c [2] 75 76 [2] 6b 6b [2] 69 6a [2] 72 6c [2] 6e 6b [2] 72 44 }

  condition:
    any of them
}