rule TTP_XOR_QUAD_CurrentVersionRun_eeb8 {
  strings:
    $key_eeb8 = { bd d7 [2] 99 d9 [2] b2 f5 [2] 9c d7 [2] 88 cc [2] 87 d6 [2] 99 cb [2] 9b ca [2] 80 cc [2] 9c cb [2] 80 e4 }

  condition:
    any of them
}