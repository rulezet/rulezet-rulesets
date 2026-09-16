rule TTP_XOR_QUAD_CurrentVersionRun_3aa5 {
  strings:
    $key_3aa5 = { 69 ca [2] 4d c4 [2] 66 e8 [2] 48 ca [2] 5c d1 [2] 53 cb [2] 4d d6 [2] 4f d7 [2] 54 d1 [2] 48 d6 [2] 54 f9 }

  condition:
    any of them
}