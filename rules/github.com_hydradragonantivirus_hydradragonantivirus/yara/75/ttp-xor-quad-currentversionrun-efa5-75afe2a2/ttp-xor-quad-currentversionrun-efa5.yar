rule TTP_XOR_QUAD_CurrentVersionRun_efa5 {
  strings:
    $key_efa5 = { bc ca [2] 98 c4 [2] b3 e8 [2] 9d ca [2] 89 d1 [2] 86 cb [2] 98 d6 [2] 9a d7 [2] 81 d1 [2] 9d d6 [2] 81 f9 }

  condition:
    any of them
}