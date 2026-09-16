rule TTP_XOR_QUAD_CurrentVersionRun_fda5 {
  strings:
    $key_fda5 = { ae ca [2] 8a c4 [2] a1 e8 [2] 8f ca [2] 9b d1 [2] 94 cb [2] 8a d6 [2] 88 d7 [2] 93 d1 [2] 8f d6 [2] 93 f9 }

  condition:
    any of them
}