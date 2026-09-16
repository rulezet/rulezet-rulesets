rule TTP_XOR_QUAD_CurrentVersionRun_eda5 {
  strings:
    $key_eda5 = { be ca [2] 9a c4 [2] b1 e8 [2] 9f ca [2] 8b d1 [2] 84 cb [2] 9a d6 [2] 98 d7 [2] 83 d1 [2] 9f d6 [2] 83 f9 }

  condition:
    any of them
}