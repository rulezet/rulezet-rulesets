rule TTP_XOR_QUAD_CurrentVersionRun_0da5 {
  strings:
    $key_0da5 = { 5e ca [2] 7a c4 [2] 51 e8 [2] 7f ca [2] 6b d1 [2] 64 cb [2] 7a d6 [2] 78 d7 [2] 63 d1 [2] 7f d6 [2] 63 f9 }

  condition:
    any of them
}