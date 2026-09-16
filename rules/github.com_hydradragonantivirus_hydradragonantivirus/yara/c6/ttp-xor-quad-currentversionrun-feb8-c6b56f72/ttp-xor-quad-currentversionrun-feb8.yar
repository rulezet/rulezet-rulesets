rule TTP_XOR_QUAD_CurrentVersionRun_feb8 {
  strings:
    $key_feb8 = { ad d7 [2] 89 d9 [2] a2 f5 [2] 8c d7 [2] 98 cc [2] 97 d6 [2] 89 cb [2] 8b ca [2] 90 cc [2] 8c cb [2] 90 e4 }

  condition:
    any of them
}