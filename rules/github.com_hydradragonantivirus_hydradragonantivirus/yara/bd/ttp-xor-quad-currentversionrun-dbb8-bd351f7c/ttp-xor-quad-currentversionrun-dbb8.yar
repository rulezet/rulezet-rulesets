rule TTP_XOR_QUAD_CurrentVersionRun_dbb8 {
  strings:
    $key_dbb8 = { 88 d7 [2] ac d9 [2] 87 f5 [2] a9 d7 [2] bd cc [2] b2 d6 [2] ac cb [2] ae ca [2] b5 cc [2] a9 cb [2] b5 e4 }

  condition:
    any of them
}