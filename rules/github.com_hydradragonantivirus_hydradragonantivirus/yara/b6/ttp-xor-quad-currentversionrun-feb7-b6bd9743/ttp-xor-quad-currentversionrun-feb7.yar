rule TTP_XOR_QUAD_CurrentVersionRun_feb7 {
  strings:
    $key_feb7 = { ad d8 [2] 89 d6 [2] a2 fa [2] 8c d8 [2] 98 c3 [2] 97 d9 [2] 89 c4 [2] 8b c5 [2] 90 c3 [2] 8c c4 [2] 90 eb }

  condition:
    any of them
}