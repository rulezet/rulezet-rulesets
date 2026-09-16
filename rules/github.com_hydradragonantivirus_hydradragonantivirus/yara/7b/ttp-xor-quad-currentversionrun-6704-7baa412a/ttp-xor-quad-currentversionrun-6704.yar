rule TTP_XOR_QUAD_CurrentVersionRun_6704 {
  strings:
    $key_6704 = { 34 6b [2] 10 65 [2] 3b 49 [2] 15 6b [2] 01 70 [2] 0e 6a [2] 10 77 [2] 12 76 [2] 09 70 [2] 15 77 [2] 09 58 }

  condition:
    any of them
}