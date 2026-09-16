rule TTP_XOR_QUAD_CurrentVersionRun_14a6 {
  strings:
    $key_14a6 = { 47 c9 [2] 63 c7 [2] 48 eb [2] 66 c9 [2] 72 d2 [2] 7d c8 [2] 63 d5 [2] 61 d4 [2] 7a d2 [2] 66 d5 [2] 7a fa }

  condition:
    any of them
}