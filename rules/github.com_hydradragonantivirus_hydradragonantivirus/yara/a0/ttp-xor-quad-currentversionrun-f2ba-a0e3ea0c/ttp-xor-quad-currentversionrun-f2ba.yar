rule TTP_XOR_QUAD_CurrentVersionRun_f2ba {
  strings:
    $key_f2ba = { a1 d5 [2] 85 db [2] ae f7 [2] 80 d5 [2] 94 ce [2] 9b d4 [2] 85 c9 [2] 87 c8 [2] 9c ce [2] 80 c9 [2] 9c e6 }

  condition:
    any of them
}