rule TTP_XOR_QUAD_CurrentVersionRun_26b8 {
  strings:
    $key_26b8 = { 75 d7 [2] 51 d9 [2] 7a f5 [2] 54 d7 [2] 40 cc [2] 4f d6 [2] 51 cb [2] 53 ca [2] 48 cc [2] 54 cb [2] 48 e4 }

  condition:
    any of them
}