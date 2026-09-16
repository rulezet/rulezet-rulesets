rule TTP_XOR_QUAD_CurrentVersionRun_00c6 {
  strings:
    $key_00c6 = { 53 a9 [2] 77 a7 [2] 5c 8b [2] 72 a9 [2] 66 b2 [2] 69 a8 [2] 77 b5 [2] 75 b4 [2] 6e b2 [2] 72 b5 [2] 6e 9a }

  condition:
    any of them
}