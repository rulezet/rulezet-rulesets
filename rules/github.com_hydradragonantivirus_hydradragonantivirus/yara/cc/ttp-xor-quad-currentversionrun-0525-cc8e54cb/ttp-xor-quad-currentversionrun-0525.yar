rule TTP_XOR_QUAD_CurrentVersionRun_0525 {
  strings:
    $key_0525 = { 56 4a [2] 72 44 [2] 59 68 [2] 77 4a [2] 63 51 [2] 6c 4b [2] 72 56 [2] 70 57 [2] 6b 51 [2] 77 56 [2] 6b 79 }

  condition:
    any of them
}