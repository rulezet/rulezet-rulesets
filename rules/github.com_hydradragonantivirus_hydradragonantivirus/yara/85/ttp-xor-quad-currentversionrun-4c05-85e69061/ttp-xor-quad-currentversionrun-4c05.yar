rule TTP_XOR_QUAD_CurrentVersionRun_4c05 {
  strings:
    $key_4c05 = { 1f 6a [2] 3b 64 [2] 10 48 [2] 3e 6a [2] 2a 71 [2] 25 6b [2] 3b 76 [2] 39 77 [2] 22 71 [2] 3e 76 [2] 22 59 }

  condition:
    any of them
}