rule TTP_XOR_QUAD_CurrentVersionRun_0504 {
  strings:
    $key_0504 = { 56 6b [2] 72 65 [2] 59 49 [2] 77 6b [2] 63 70 [2] 6c 6a [2] 72 77 [2] 70 76 [2] 6b 70 [2] 77 77 [2] 6b 58 }

  condition:
    any of them
}