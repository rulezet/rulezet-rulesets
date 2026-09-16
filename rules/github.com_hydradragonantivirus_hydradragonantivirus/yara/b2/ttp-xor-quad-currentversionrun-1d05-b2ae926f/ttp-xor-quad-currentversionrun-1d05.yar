rule TTP_XOR_QUAD_CurrentVersionRun_1d05 {
  strings:
    $key_1d05 = { 4e 6a [2] 6a 64 [2] 41 48 [2] 6f 6a [2] 7b 71 [2] 74 6b [2] 6a 76 [2] 68 77 [2] 73 71 [2] 6f 76 [2] 73 59 }

  condition:
    any of them
}