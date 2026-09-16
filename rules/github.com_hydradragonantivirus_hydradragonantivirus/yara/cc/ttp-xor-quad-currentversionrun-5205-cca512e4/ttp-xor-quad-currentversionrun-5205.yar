rule TTP_XOR_QUAD_CurrentVersionRun_5205 {
  strings:
    $key_5205 = { 01 6a [2] 25 64 [2] 0e 48 [2] 20 6a [2] 34 71 [2] 3b 6b [2] 25 76 [2] 27 77 [2] 3c 71 [2] 20 76 [2] 3c 59 }

  condition:
    any of them
}