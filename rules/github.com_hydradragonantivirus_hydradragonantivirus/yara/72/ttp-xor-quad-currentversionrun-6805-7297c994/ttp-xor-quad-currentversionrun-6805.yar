rule TTP_XOR_QUAD_CurrentVersionRun_6805 {
  strings:
    $key_6805 = { 3b 6a [2] 1f 64 [2] 34 48 [2] 1a 6a [2] 0e 71 [2] 01 6b [2] 1f 76 [2] 1d 77 [2] 06 71 [2] 1a 76 [2] 06 59 }

  condition:
    any of them
}