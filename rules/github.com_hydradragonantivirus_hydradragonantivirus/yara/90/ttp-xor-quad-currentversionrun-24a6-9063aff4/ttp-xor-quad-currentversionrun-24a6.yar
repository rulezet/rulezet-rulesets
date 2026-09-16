rule TTP_XOR_QUAD_CurrentVersionRun_24a6 {
  strings:
    $key_24a6 = { 77 c9 [2] 53 c7 [2] 78 eb [2] 56 c9 [2] 42 d2 [2] 4d c8 [2] 53 d5 [2] 51 d4 [2] 4a d2 [2] 56 d5 [2] 4a fa }

  condition:
    any of them
}