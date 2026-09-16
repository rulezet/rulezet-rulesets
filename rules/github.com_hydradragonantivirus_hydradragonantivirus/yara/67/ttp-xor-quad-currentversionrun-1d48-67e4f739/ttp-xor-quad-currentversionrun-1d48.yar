rule TTP_XOR_QUAD_CurrentVersionRun_1d48 {
  strings:
    $key_1d48 = { 4e 27 [2] 6a 29 [2] 41 05 [2] 6f 27 [2] 7b 3c [2] 74 26 [2] 6a 3b [2] 68 3a [2] 73 3c [2] 6f 3b [2] 73 14 }

  condition:
    any of them
}