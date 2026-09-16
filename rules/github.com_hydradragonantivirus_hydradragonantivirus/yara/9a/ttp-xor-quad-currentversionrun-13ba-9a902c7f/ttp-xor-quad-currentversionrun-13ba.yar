rule TTP_XOR_QUAD_CurrentVersionRun_13ba {
  strings:
    $key_13ba = { 40 d5 [2] 64 db [2] 4f f7 [2] 61 d5 [2] 75 ce [2] 7a d4 [2] 64 c9 [2] 66 c8 [2] 7d ce [2] 61 c9 [2] 7d e6 }

  condition:
    any of them
}