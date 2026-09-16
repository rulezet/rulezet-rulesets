rule TTP_XOR_QUAD_CurrentVersionRun_3da5 {
  strings:
    $key_3da5 = { 6e ca [2] 4a c4 [2] 61 e8 [2] 4f ca [2] 5b d1 [2] 54 cb [2] 4a d6 [2] 48 d7 [2] 53 d1 [2] 4f d6 [2] 53 f9 }

  condition:
    any of them
}