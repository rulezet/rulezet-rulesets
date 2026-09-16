rule TTP_XOR_QUAD_CurrentVersionRun_e5ba {
  strings:
    $key_e5ba = { b6 d5 [2] 92 db [2] b9 f7 [2] 97 d5 [2] 83 ce [2] 8c d4 [2] 92 c9 [2] 90 c8 [2] 8b ce [2] 97 c9 [2] 8b e6 }

  condition:
    any of them
}