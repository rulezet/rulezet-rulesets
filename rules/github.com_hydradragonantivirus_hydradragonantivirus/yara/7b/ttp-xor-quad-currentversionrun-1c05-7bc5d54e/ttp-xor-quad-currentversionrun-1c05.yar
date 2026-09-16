rule TTP_XOR_QUAD_CurrentVersionRun_1c05 {
  strings:
    $key_1c05 = { 4f 6a [2] 6b 64 [2] 40 48 [2] 6e 6a [2] 7a 71 [2] 75 6b [2] 6b 76 [2] 69 77 [2] 72 71 [2] 6e 76 [2] 72 59 }

  condition:
    any of them
}