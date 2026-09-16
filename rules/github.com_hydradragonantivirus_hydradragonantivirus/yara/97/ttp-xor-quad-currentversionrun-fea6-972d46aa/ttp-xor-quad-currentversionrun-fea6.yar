rule TTP_XOR_QUAD_CurrentVersionRun_fea6 {
  strings:
    $key_fea6 = { ad c9 [2] 89 c7 [2] a2 eb [2] 8c c9 [2] 98 d2 [2] 97 c8 [2] 89 d5 [2] 8b d4 [2] 90 d2 [2] 8c d5 [2] 90 fa }

  condition:
    any of them
}